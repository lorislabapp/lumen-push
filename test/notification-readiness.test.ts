import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { channelIDForSecret, sanitizeCameraDisplayName, type Env } from "../src/index";
import relayFixture from "./fixtures/relay-generated-review.json";
class KV {
  values = new Map<string,string>();
  async get(key:string) { return this.values.get(key) ?? null; }
  async put(key:string, value:string) { this.values.set(key,value); }
  async delete(key:string) { this.values.delete(key); }
}
const secret = "12".repeat(16);
const token = "ab".repeat(32);
const envelope = (extra:Record<string,unknown>={}) => ({source:"relay", sourceSchema:"frigate-review-v1", reviewId:"review-car", reviewSeverity:"alert", eventId:"car-1", camera:"swann_ch16", label:"car", score:0.75, stationary:false, zones:[], detected_at:Date.now()/1000,...extra});
async function setup(tokens=[token]) {
  const devices = new KV(), rate = new KV();
  const pair = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const key = new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
  const env = {KILL_SWITCH:"0",APNS_KEY:`-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...key))}\n-----END PRIVATE KEY-----`,APNS_KEY_ID:"TEST",APNS_TEAM_ID:"TEST",APNS_BUNDLE_ID:"test.lumen",DEVICES:devices,RATE_LIMIT:rate,RATE_LIMIT_SECONDS:"0",AUTOMATION_POLICY_KEK_B64:btoa(String.fromCharCode(...Array(32).fill(66)))} as unknown as Env;
  const channel = await channelIDForSecret(secret);
  await devices.put(`devices:${channel}`,JSON.stringify(tokens.map(token=>({token,sandbox:false,registered_at:0}))));
  const cache = new Map<string,Response>();
  vi.stubGlobal("caches",{default:{match:async (key:string)=>cache.get(key)?.clone(),put:async(key:string,value:Response)=>{cache.set(key,value.clone());}}});
  const fetch = vi.fn(async (_url:unknown,_init?:RequestInit)=>new Response(null,{status:200}));
  vi.stubGlobal("fetch",fetch);
  const send = (body:unknown) => worker.fetch(new Request(`https://push.test/v2/notify/${channel}`,{method:"POST",body:JSON.stringify(body)}),env);
  return {env,channel,send,fetch};
}
afterEach(()=>vi.unstubAllGlobals());
describe("ghost-push delivery boundary",()=>{
  it("delivers the actual Python relay's correlated envelope unchanged",async()=>{
    const {send,fetch}=await setup();
    expect((await send({...relayFixture,detected_at:Date.now()/1000})).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
    const payload=JSON.parse(fetch.mock.calls[0][1]!.body as string);
    expect(payload.reviewId).toBe(relayFixture.reviewId);
    expect(payload.eventId).toBe(relayFixture.eventId);
    expect(payload.top_score).toBe(.75);
    expect(payload.zones).toEqual(["driveway"]);
  });
  it("keeps legacy delivery explicit without manufacturing Review identity",async()=>{
    const {send,fetch}=await setup();
    const raw={id:"raw-car",camera:"driveway",label:"car",top_score:.76,stationary:false,start_time:Date.now()/1000};
    expect((await send(raw)).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
    const payload=JSON.parse(fetch.mock.calls[0][1]!.body as string);
    expect(payload.source).toBe("cloudflare-relay");
    expect(payload.sourceSchema).toBeUndefined();
    expect(payload.reviewId).toBeUndefined();
    expect(payload.reviewSeverity).toBeUndefined();
    expect(payload.top_score).toBe(.76);
  });
  it("deduplicates a Review transition even when its representative changes",async()=>{
    const {send,fetch}=await setup();
    expect((await send(envelope())).status).toBe(200);
    expect((await send(envelope({eventId:"car-2"}))).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect((await send(envelope({reviewSeverity:"detection"}))).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it("keeps failed transport retryable and does not promote unsigned critical flags",async()=>{
    const {send,fetch}=await setup();
    fetch.mockResolvedValueOnce(new Response(null,{status:503}));
    expect((await send(envelope())).status).toBe(502);
    expect((await send(envelope({lumen_critical:true}))).status).toBe(200);
    const payload=JSON.parse(fetch.mock.calls[1][1]!.body as string);
    expect(payload.aps["interruption-level"]).not.toBe("critical");
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it("coalesces concurrent requests for one device and Review transition",async()=>{
    const {send,fetch}=await setup();
    const results=await Promise.all(Array.from({length:8},()=>send(envelope())));
    expect(results.every(r=>r.status===200)).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("retries partial fan-out without re-alerting the successful device",async()=>{
    const second="cd".repeat(32);
    const {send,fetch}=await setup([token,second]);
    fetch.mockImplementationOnce(async()=>new Response(null,{status:200}));
    fetch.mockImplementationOnce(async()=>new Response(null,{status:503}));
    expect((await send(envelope())).status).toBe(502);
    expect((await send(envelope())).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(String(fetch.mock.calls[2][0])).toContain(second);
  });
  it("does not create a banner from an orphan enrichment",async()=>{
    const {send,fetch}=await setup();
    expect((await send(envelope({isEnrichment:true}))).status).toBe(200);
    expect(fetch).not.toHaveBeenCalled();
    await send(envelope());
    await send(envelope({isEnrichment:true,description:"A car arrived"}));
    await send(envelope({isEnrichment:true,description:"Another update"}));
    expect(fetch).toHaveBeenCalledTimes(2);
    const payload=JSON.parse(fetch.mock.calls[1][1]!.body as string);
    expect(payload.aps.sound).toBeUndefined();
    expect(payload.aps["interruption-level"]).toBe("passive");
  });
  it("enforces an explicit per-channel person/car 75 percent allowlist before APNs",async()=>{
    const {env,channel,send,fetch}=await setup();
    const condition=(condition:unknown)=>({kind:"condition",condition});
    const allow={kind:"all",parts:[{kind:"any",parts:[condition({label:{name:"person"}}),condition({label:{name:"car"}})]},condition({confidence:{comparison:"gte",value:.75}}),{kind:"not",expression:condition({stationary:{stationary:true}})}]};
    // Suppression has no cooldown: a negative policy must remain in force.
    const rules=[{id:"eligibility",name:"Notification eligibility",schemaVersion:4,enabled:true,sideEffectAuthority:"bridgeRequired",cooldownSeconds:0,branches:[{id:"reject",kind:"if",expression:{kind:"not",expression:allow},actions:[{suppressNotification:{}}]}]}];
    const bytes=new TextEncoder().encode(JSON.stringify(rules));
    const hash=`sha256:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)),x=>x.toString(16).padStart(2,"0")).join("")}`;
    const upload={schema:"lumen-automation-policy-v1",revision:1,hash,policyBase64:btoa(String.fromCharCode(...bytes)),decisionKeyBase64:btoa(String.fromCharCode(...Array(32).fill(7))),timeZone:"UTC"};
    expect((await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/automation-policy`,{method:"PUT",headers:{Authorization:`Bearer ${secret}`},body:JSON.stringify(upload)}),env)).status).toBe(200);
    for(const extra of [{score:.71},{score:.74},{label:"dog",score:.99},{stationary:true}]) {
      expect((await send(envelope(extra))).status).toBe(200);
    }
    expect(fetch).not.toHaveBeenCalled();
    for(const [i,extra] of [{score:.75},{score:.76},{label:"person",score:.75}].entries()) {
      expect((await send(envelope({...extra,reviewId:`allowed-${i}`}))).status).toBe(200);
    }
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});


describe("device filtering before APNs",()=>{
  async function filteredSetup(overrides:Record<string,unknown>={}) {
    const setupResult=await setup();
    const {env,channel}=setupResult;
    const policy={schema:"lumen-delivery-filter-v1",enabled:true,isPassthrough:false,reviewAlertsOnly:true,
      globalDefaults:{enabled:true,labels:["car","cat","person"],minScore:.8,criticalMinScore:.85,ignoreStationary:true,cooldownSeconds:120},cameras:{},...overrides};
    const response=await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/devices`,{method:"POST",headers:{Authorization:`Bearer ${secret}`},body:JSON.stringify({token,sandbox:false,platform:"ios",filterPolicy:policy,filterPolicyHash:"a".repeat(64)})}),env);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({filter_policy_version:1,filter_policy_hash:"a".repeat(64)});
    return setupResult;
  }
  it("sends no APNs request for below-threshold, stationary or non-alert Review candidates",async()=>{
    const {send,fetch}=await filteredSetup();
    for(const candidate of [{score:.71,stationary:false},{score:.76,stationary:false},{score:.78,stationary:false},{score:.9,stationary:true},{score:.9,stationary:false,reviewSeverity:"detection"}]) {
      expect((await send(envelope(candidate))).status).toBe(200);
    }
    expect(fetch).not.toHaveBeenCalled();
  });
  it("never admits raw objects when Review-alert-only is selected",async()=>{
    const {send,fetch}=await filteredSetup();
    const raw={id:"raw-car",camera:"driveway",label:"car",top_score:.95,stationary:false,start_time:Date.now()/1000};
    expect((await send(raw)).status).toBe(200);
    expect(fetch).not.toHaveBeenCalled();
  });
  it("allows a legitimate alert and blocks a repeated camera-label event within cooldown",async()=>{
    const {send,fetch}=await filteredSetup();
    expect((await send(envelope({score:.9,stationary:false}))).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect((await send(envelope({score:.92,stationary:false,reviewId:"next-review",eventId:"next-car"}))).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("downgrades critical presentation without discarding a valid normal-confidence alert",async()=>{
    const {send,fetch}=await filteredSetup();
    expect((await send(envelope({label:"person",score:.82,stationary:false}))).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
    const payload=JSON.parse(fetch.mock.calls[0][1]!.body as string);
    expect(payload.aps["interruption-level"]).not.toBe("critical");
  });
});

describe("per-camera rate limit and relay-facing outcomes",()=>{
  const second="cd".repeat(32);
  const at=(ms:number)=>vi.setSystemTime(new Date(1_800_000_000_000+ms));
  afterEach(()=>vi.useRealTimers());
  async function limited(tokens=[token]) {
    vi.useFakeTimers({toFake:["Date"]}); at(0);
    const result=await setup(tokens);
    result.env.RATE_LIMIT_SECONDS="5";
    return result;
  }
  it("delivers two cameras 2.6 s apart to both phones",async()=>{
    const {send,fetch}=await limited([token,second]);
    const walkway=await send(envelope({camera:"main_walkway",reviewId:"r-walkway",eventId:"e-walkway",label:"person"}));
    at(2_600);
    const porch=await send(envelope({camera:"back_porch",reviewId:"r-porch",eventId:"e-porch",label:"person"}));
    expect(walkway.status).toBe(200);
    expect(porch.status).toBe(200);
    expect(await walkway.json()).toMatchObject({ok:true,delivered:2,suppressed:0});
    expect(await porch.json()).toMatchObject({ok:true,delivered:2,suppressed:0});
    expect(fetch).toHaveBeenCalledTimes(4);
    const subtitles=fetch.mock.calls.map(call=>JSON.parse(call[1]!.body as string).aps.alert.subtitle);
    expect(subtitles.filter(s=>s==="Back Porch")).toHaveLength(2);
  });
  it("still suppresses the same camera inside the window, then releases it",async()=>{
    const {send,fetch}=await limited();
    expect(await (await send(envelope({reviewId:"r1"}))).json()).toMatchObject({delivered:1});
    at(2_600);
    const again=await send(envelope({reviewId:"r2",eventId:"car-2",camera:" SWANN_CH16 "}));
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ok:true,delivered:0,suppressed:1,outcomes:[{outcome:"rate_limited",reason:"same_camera_within_rate_limit"}]});
    expect(fetch).toHaveBeenCalledTimes(1);
    at(5_100);
    expect(await (await send(envelope({reviewId:"r3",eventId:"car-3"}))).json()).toMatchObject({delivered:1});
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it("returns a closed JSON shape with no token, id or camera",async()=>{
    const {send,fetch}=await limited([token,second]);
    // Fail the second phone by URL: concurrent fan-out order is not deterministic.
    fetch.mockImplementation(async(url:unknown)=>new Response(null,{status:String(url).includes(second)&&fetch.mock.calls.length<=2?503:200}));
    const response=await send(envelope({reviewId:"shape",eventId:"shape-event"}));
    expect(response.status).toBe(502);
    expect(response.headers.get("content-type")).toBe("application/json");
    const text=await response.text();
    for(const secretish of [token,second,"shape","swann",secret]) expect(text.toLowerCase()).not.toContain(secretish);
    const body=JSON.parse(text);
    expect(Object.keys(body).sort()).toEqual(["delivered","ok","outcomes","suppressed"]);
    expect(body).toEqual({ok:false,delivered:1,suppressed:0,outcomes:[{outcome:"sent",reason:"apns_accepted"},{outcome:"failed",reason:"apns_status_503"}]});
    const retry=await send(envelope({reviewId:"shape",eventId:"shape-event"}));
    expect(await retry.json()).toEqual({ok:true,delivered:1,suppressed:1,outcomes:[{outcome:"duplicate",reason:"already_delivered"},{outcome:"sent",reason:"apns_accepted"}]});
  });
  it("answers a repeated test within 60 s with an explicit reason",async()=>{
    const {channel,env,fetch}=await limited();
    const test=()=>worker.fetch(new Request(`https://push.test/v2/channels/${channel}/test`,{method:"POST",headers:{Authorization:`Bearer ${secret}`}}),env);
    expect(await (await test()).json()).toEqual({ok:true,delivered:1});
    const again=await test();
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ok:true,delivered:0,reason:"test_recently_sent"});
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe("camera display name",()=>{
  it("sanitizes and bounds the name",()=>{
    expect(sanitizeCameraDisplayName("  Back\u0000 Porch‮\n ")).toBe("Back Porch");
    expect(sanitizeCameraDisplayName("x".repeat(100))).toBe("x".repeat(64));
    expect(sanitizeCameraDisplayName("\u0007\t ")).toBeUndefined();
    expect(sanitizeCameraDisplayName(42)).toBeUndefined();
    expect(sanitizeCameraDisplayName("y".repeat(2000))).toBeUndefined();
  });
  it("uses the sanitized name for the alert and forwards it to the extension",async()=>{
    const {send,fetch}=await setup();
    expect((await send(envelope({camera_display_name:"  Back\u0007 Porch‮ "}))).status).toBe(200);
    const payload=JSON.parse(fetch.mock.calls[0][1]!.body as string);
    expect(payload.aps.alert.subtitle).toBe("Back Porch");
    expect(payload.camera_display_name).toBe("Back Porch");
    expect(payload.camera).toBe("swann_ch16");
    expect(payload.aps["thread-id"]).toBe("swann_ch16");
  });
  it("accepts the snake_case relay shape",async()=>{
    const {send,fetch}=await setup();
    const raw={type:"new",after:{id:"e1",camera:"back_porch",label:"person",top_score:.9,start_time:Date.now()/1000,source_schema:"frigate-review-v1",review_id:"r1",review_severity:"alert",camera_display_name:"Porche arrière"}};
    expect((await send(raw)).status).toBe(200);
    const payload=JSON.parse(fetch.mock.calls[0][1]!.body as string);
    expect(payload.aps.alert.subtitle).toBe("Porche arrière");
  });
  it("falls back to the prettified id when the name is unusable, still alerting",async()=>{
    const {send,fetch}=await setup();
    expect((await send(envelope({camera_display_name:123}))).status).toBe(200);
    const payload=JSON.parse(fetch.mock.calls[0][1]!.body as string);
    expect(payload.aps.alert.subtitle).toBe("Swann Ch16");
    expect("camera_display_name" in payload).toBe(false);
  });
  it("leaves an old payload's APNs body unchanged",async()=>{
    const {send,fetch}=await setup();
    expect((await send(envelope())).status).toBe(200);
    const payload=JSON.parse(fetch.mock.calls[0][1]!.body as string);
    expect(Object.keys(payload)).toEqual(["aps","eventId","sourceSchema","reviewId","reviewSeverity","camera","label","zones","top_score","stationary","isEnrichment","detected_at","source","classification"]);
    expect(payload.aps.alert).toEqual({title:"Car Detected",subtitle:"Swann Ch16",body:"Confidence: 75%"});
  });
});

describe("last notify record (opt-in)",()=>{
  const statusOf=async(env:Env,channel:string)=>(await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/status`,{headers:{Authorization:`Bearer ${secret}`}}),env)).json() as Promise<Record<string,any>>;
  it("keeps nothing by default",async()=>{
    const {env,channel,send}=await setup();
    await send(envelope());
    expect([...(env.DEVICES as unknown as KV).values.keys()].some(k=>k.startsWith("last-notify:"))).toBe(false);
    expect(await statusOf(env,channel)).toMatchObject({lastNotify:null,deliveryHistoryRetained:false});
  });
  it("when enabled, stores one minimal record and writes at most once a minute",async()=>{
    const {env,channel,send}=await setup();
    env.LAST_NOTIFY_RETENTION="1";
    const kv=env.DEVICES as unknown as KV;
    const put=vi.spyOn(kv,"put");
    await send(envelope());
    await send(envelope({reviewId:"r-2",camera:"other"}));
    expect(put.mock.calls.filter(([k])=>k.startsWith("last-notify:"))).toHaveLength(1);
    const record=kv.values.get(`last-notify:${channel}`)!;
    expect(Object.keys(JSON.parse(record)).sort()).toEqual(["at","reason","status"]);
    expect(record).not.toContain("swann");
    const status=await statusOf(env,channel);
    expect(status.deliveryHistoryRetained).toBe(true);
    expect(status.lastNotify).toMatchObject({status:200,reason:"delivered",userAgent:null});
  });
  it("never creates a record for a channel with no device",async()=>{
    const {env}=await setup();
    env.LAST_NOTIFY_RETENTION="1";
    const empty=await channelIDForSecret("34".repeat(16));
    await worker.fetch(new Request(`https://push.test/v2/notify/${empty}`,{method:"POST",body:JSON.stringify(envelope())}),env);
    expect((env.DEVICES as unknown as KV).values.has(`last-notify:${empty}`)).toBe(false);
  });
});

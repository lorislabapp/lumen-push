import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { channelIDForSecret, type Env } from "../src/index";
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
  it("never sends raw CH16 detections at 71-76 percent to APNs on either route",async()=>{
    const {env,send,fetch}=await setup();
    for(const score of [.71,.74,.75,.76]) {
      const raw={id:`car-${score}`,camera:"swann_ch16",label:"car",top_score:score,zones:[],start_time:Date.now()/1000};
      for(const body of [raw,{type:"new",after:raw}]) {
        expect((await send(body)).status).toBe(400);
        expect((await worker.fetch(new Request(`https://push.test/v1/notify/${secret}/${token}`,{method:"POST",body:JSON.stringify(body)}),env)).status).toBe(400);
      }
    }
    expect(fetch).not.toHaveBeenCalled();
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

import { afterEach, describe, expect, it, vi } from "vitest";
import current, { channelIDForSecret, type Env } from "../src/index";
import { pathToFileURL } from "node:url";
const implementations: [string, typeof current][] = [["development", current]];
const candidate = process.env.LUMEN_PRODUCTION_PRIVACY_MODULE;
if (candidate) implementations.push(["production hotfix", (await import(/* @vite-ignore */ pathToFileURL(candidate).href)).default]);

class KV {
  values = new Map<string, string>();
  writes: {key: string; value: string; options?: {expirationTtl?: number}}[] = [];
  reads: string[] = [];
  async get(key: string) { this.reads.push(key); return this.values.get(key) ?? null; }
  async put(key: string, value: string, options?: {expirationTtl?: number}) {
    this.values.set(key, value); this.writes.push({key, value, options});
  }
  async delete(key: string) { this.values.delete(key); }
}
const secret = "45".repeat(16), token = "ab".repeat(32);
const event = (extra = {}) => ({source:"relay",sourceSchema:"frigate-review-v1",reviewId:"privacy-review",reviewSeverity:"alert",eventId:"private-event-sentinel",camera:"private-camera-sentinel",label:"person",score:.9,detected_at:Date.now()/1000,...extra});
async function setup(worker: typeof current) {
  const devices = new KV(), rate = new KV();
  const pair = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const key = new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
  const analytics = vi.fn(() => { throw new Error("Analytics must never be used"); });
  const env = {KILL_SWITCH:"0",APNS_KEY:`-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...key))}\n-----END PRIVATE KEY-----`,APNS_KEY_ID:"TEST",APNS_TEAM_ID:"TEST",APNS_BUNDLE_ID:"test.lumen",DEVICES:devices,RATE_LIMIT:rate,RATE_LIMIT_SECONDS:"0",NOTIF_STATS:{writeDataPoint:analytics},CF_ACCOUNT_ID:"test",CF_ANALYTICS_TOKEN:"retired-test",SLACK_WEBHOOK_URL:"https://slack.invalid/never",STATS_TOKEN:"retired-test"} as unknown as Env;
  const channel = await channelIDForSecret(secret);
  await devices.put(`devices:${channel}`,JSON.stringify([{token,sandbox:false,registered_at:0}]));
  devices.writes=[];
  const cache = new Map<string,Response>();
  vi.stubGlobal("caches",{default:{match:async(key:string)=>cache.get(key)?.clone(),put:async(key:string,v:Response)=>{cache.set(key,v.clone());}}});
  const fetch = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response(null,{status:200}));
  vi.stubGlobal("fetch",fetch);
  const log=vi.spyOn(console,"log").mockImplementation(()=>{});
  const error=vi.spyOn(console,"error").mockImplementation(()=>{});
  const send = (body=event(), v1=false) => worker.fetch(new Request(v1?`https://push.test/v1/notify/${secret}/${token}`:`https://push.test/v2/notify/${channel}`,{method:"POST",headers:{"CF-IPCountry":"ZZ","User-Agent":"private-agent-sentinel"},body:JSON.stringify(body)}),env);
  return {env,channel,devices,rate,fetch,analytics,log,error,send};
}
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllGlobals();});

describe.each(implementations)("notification privacy: %s",(_name,worker)=>{
  it("delivers v1/v2 without analytics even if an obsolete binding remains",async()=>{
    const s=await setup(worker);
    expect((await s.send(event())).status).toBe(200);
    expect((await s.send(event({reviewId:"second"}),true)).status).toBe(200);
    expect(s.fetch).toHaveBeenCalledTimes(2);
    expect(s.fetch.mock.calls.every(([url])=>String(url).startsWith("https://api.push.apple.com/3/device/"))).toBe(true);
    expect(s.analytics).not.toHaveBeenCalled();
    expect(s.devices.writes).toHaveLength(0);
    expect(s.log).not.toHaveBeenCalled();expect(s.error).not.toHaveBeenCalled();
  });
  it("does not export historical analytics through dashboard or delayed cron",async()=>{
    const s=await setup(worker);
    for(const path of ["/stats","/stats?token=retired-test","/stats?token=retired-test&format=json"]) {
      const r=await worker.fetch(new Request("https://push.test"+path),s.env);
      expect(r.status).toBe(410);expect(r.headers.get("cache-control")).toBe("no-store");
    }
    await worker.scheduled();
    expect(s.fetch).not.toHaveBeenCalled();expect(s.analytics).not.toHaveBeenCalled();
  });
  it("neither reads nor exposes existing channel delivery history",async()=>{
    const s=await setup(worker);
    await s.devices.put(`notify-status:${s.channel}`,JSON.stringify({status:200,reason:"private-camera-sentinel",at:Date.now(),userAgent:"private-agent-sentinel"}));
    s.devices.reads=[];
    const response=await worker.fetch(new Request(`https://push.test/v2/channels/${s.channel}/status`,{headers:{Authorization:`Bearer ${secret}`}}),s.env);
    const body=await response.json() as Record<string,unknown>;
    expect(body.lastNotify).toBeNull();expect(body.deliveryHistoryRetained).toBe(false);expect(body.deviceCount).toBe(1);
    expect(s.devices.reads.some(k=>k.startsWith("notify-status:"))).toBe(false);
    expect(JSON.stringify(body)).not.toContain("sentinel");
  });
  it("preserves temporary images without leaking names into logs or history",async()=>{
    const s=await setup(worker);
    expect((await s.send(event({compressed_snapshot:"A".repeat(6000)}))).status).toBe(200);
    const snapshot=s.rate.writes.find(w=>w.key.startsWith("snapshot-v2:"))!;
    expect(snapshot.options?.expirationTtl).toBe(3600);
    expect(snapshot.key).not.toContain("sentinel");
    const payload=JSON.parse(s.fetch.mock.calls[0][1]!.body as string);
    expect(payload.camera).toBe("private-camera-sentinel");
    const url=payload.compressed_snapshot_url;
    expect((await worker.fetch(new Request(url),s.env)).status).toBe(200);
    expect((await worker.fetch(new Request(url),s.env)).status).toBe(404);
    expect(s.log).not.toHaveBeenCalled();expect(s.error).not.toHaveBeenCalled();expect(s.analytics).not.toHaveBeenCalled();
  });
  it("does not log transport errors or rejected/stale events",async()=>{
    const s=await setup(worker);
    s.fetch.mockRejectedValueOnce(new Error(`private-camera-sentinel https://api.push.apple.com/3/device/${token}`));
    expect((await s.send()).status).toBe(502);
    expect((await s.send(event({detected_at:Date.now()/1000-3600}))).status).toBe(200);
    expect(s.log).not.toHaveBeenCalled();expect(s.error).not.toHaveBeenCalled();expect(s.analytics).not.toHaveBeenCalled();
  });
  it("still unregisters a user's exact device",async()=>{
    const s=await setup(worker);
    const response=await worker.fetch(new Request(`https://push.test/v2/channels/${s.channel}/devices`,{method:"DELETE",headers:{Authorization:`Bearer ${secret}`},body:JSON.stringify({token,sandbox:false})}),s.env);
    expect(response.status).toBe(204);
    expect(JSON.parse(await s.devices.get(`devices:${s.channel}`)??"[]")).toHaveLength(0);
  });
});

import { describe, expect, it } from "vitest";
import { deliveryFilterDecision, validateDeliveryFilterPolicy, type DeliveryFilterPolicy } from "../src/deliveryFilter";
const camera = {enabled:true,labels:["car","cat","person"],minScore:.8,criticalMinScore:.85,ignoreStationary:true,cooldownSeconds:120};
const policy:DeliveryFilterPolicy={schema:"lumen-delivery-filter-v1",enabled:true,isPassthrough:false,reviewAlertsOnly:true,globalDefaults:camera,cameras:{}};
const event={camera:"driveway",label:"car",score:.9,stationary:false,reviewSeverity:"alert"};
describe("pre-APNs device policy",()=>{
 it("rejects Simon's low-confidence examples and preserves the exact boundary",()=>{
  for(const score of [.71,.76,.78]) expect(deliveryFilterDecision(policy,{...event,score})).toBe("confidence");
  expect(deliveryFilterDecision(policy,{...event,score:.8})).toBeNull();
 });
 it("rejects stationary and unknown motion, never parses GenAI text",()=>{
  for(const stationary of [true,undefined,null]) expect(deliveryFilterDecision(policy,{...event,stationary})).toBe("stationary-or-unknown");
  expect(deliveryFilterDecision(policy,event)).toBeNull();
 });
 it("requires Review alert and selected label",()=>{
  expect(deliveryFilterDecision(policy,{...event,reviewSeverity:"detection"})).toBe("review-alert-required");
  expect(deliveryFilterDecision(policy,{...event,label:"dog"})).toBe("label");
 });
 it("retains explicit Server Defaults while honoring a disabled device",()=>{
  expect(deliveryFilterDecision({...policy,isPassthrough:true},{...event,score:.3})).toBeNull();
  expect(deliveryFilterDecision({...policy,enabled:false,isPassthrough:true},event)).toBe("disabled");
  expect(deliveryFilterDecision(undefined,event)).toBeNull();
 });
 it("validates and persists only allowlisted settings",()=>{
  expect(validateDeliveryFilterPolicy({...policy,password:"secret"})).toEqual(policy);
  for(const minScore of [NaN,Infinity,-1,80]) expect(validateDeliveryFilterPolicy({...policy,globalDefaults:{...camera,minScore}})).toBeNull();
  expect(validateDeliveryFilterPolicy({...policy,cameras:JSON.parse('{"__proto__":{}}')})).toBeNull();
  expect(validateDeliveryFilterPolicy({...policy,globalDefaults:{...camera,cooldownSeconds:-1}})).toBeNull();
 });
});

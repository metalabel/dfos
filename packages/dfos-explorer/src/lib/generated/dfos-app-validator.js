/* GENERATED — do not edit.
 * Source: schemas/dfos-app.v1.json
 * Regenerate: pnpm --filter @metalabel/dfos-explorer schema:build
 */
"use strict";
export const validate = validate20;
export default validate20;
const schema31 = {"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://schemas.dfos.com/dfos-app/v1","title":"DFOS App Description","description":"The `/.well-known/dfos-app.json` application description document for Sign In With DFOS — served over https from the application's own origin, where the domain vouches for itself. STRUCTURAL VALIDATION ONLY: this schema checks shape, not truth. It cannot verify that `identity_chain` folds into a valid identity chain, that `client_did` equals the DID derived from the chain's genesis operation, or that each carried operation respects the protocol's per-operation size cap — those are consumption-time checks defined by the SIWD specification (https://protocol.dfos.com/siwd), which remains normative. A document this schema accepts can still be invalid at consumption. The member set is closed (`additionalProperties: false`), making the spec's closed-registry rule mechanically checkable: a consumer MAY treat a document carrying unrecognized members as invalid.","type":"object","required":["name","redirect_uris"],"properties":{"name":{"type":"string","minLength":1,"description":"Display name — the application's own claim about itself. Nothing in the spec vouches for it; the serving domain remains the phishing-relevant binding."},"redirect_uris":{"type":"array","minItems":1,"items":{"type":"string","format":"uri"},"description":"Exact-match allowlist of the redirect targets this origin will accept callbacks at. Exact means exact: scheme, host, path, trailing slash included."},"client_did":{"type":"string","pattern":"^did:dfos:[2346789acdefhknrtvz]{31}$","description":"The application's own DFOS DID. Optional at scope=identity; required whenever a credential-returning scope would name this application as audience. When `identity_chain` is present, this MUST equal the DID derived from the chain's genesis operation — a cryptographic check this schema cannot perform."},"identity_chain":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string","minLength":1},"description":"The application identity's full ordered operation log, genesis first, carried as bare identity-operation JWS strings — never a fragment or a suffix. Capped at 100 operations (the SIWD carriage cap). Whether the strings fold into a valid chain deriving `client_did` is a consumption-time cryptographic check, not a structural one."}},"dependentRequired":{"identity_chain":["client_did"]},"additionalProperties":false};
const func1 = (str) => {
  const len = str.length;
  let length = 0;
  let pos = 0;
  while (pos < len) {
    length++;
    let value = str.charCodeAt(pos++);
    if (value >= 0xd800 && value <= 0xdbff && pos < len) {
      value = str.charCodeAt(pos);
      if ((value & 0xfc00) === 0xdc00) pos++;
    }
  }
  return length;
};
const formats0 = /^(?:[a-z][a-z0-9+\-.]*:)(?:\/?\/)?[^\s]*$/i;
const pattern4 = new RegExp("^did:dfos:[2346789acdefhknrtvz]{31}$", "u");

function validate20(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
/*# sourceURL="https://schemas.dfos.com/dfos-app/v1" */;
let vErrors = null;
let errors = 0;
const evaluated0 = validate20.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
if(data && typeof data == "object" && !Array.isArray(data)){
if(data.name === undefined){
const err0 = {instancePath,schemaPath:"#/required",keyword:"required",params:{missingProperty: "name"},message:"must have required property '"+"name"+"'"};
if(vErrors === null){
vErrors = [err0];
}
else {
vErrors.push(err0);
}
errors++;
}
if(data.redirect_uris === undefined){
const err1 = {instancePath,schemaPath:"#/required",keyword:"required",params:{missingProperty: "redirect_uris"},message:"must have required property '"+"redirect_uris"+"'"};
if(vErrors === null){
vErrors = [err1];
}
else {
vErrors.push(err1);
}
errors++;
}
for(const key0 in data){
if(!((((key0 === "name") || (key0 === "redirect_uris")) || (key0 === "client_did")) || (key0 === "identity_chain"))){
const err2 = {instancePath,schemaPath:"#/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err2];
}
else {
vErrors.push(err2);
}
errors++;
}
}
if(data.name !== undefined){
let data0 = data.name;
if(typeof data0 === "string"){
if(func1(data0) < 1){
const err3 = {instancePath:instancePath+"/name",schemaPath:"#/properties/name/minLength",keyword:"minLength",params:{limit: 1},message:"must NOT have fewer than 1 characters"};
if(vErrors === null){
vErrors = [err3];
}
else {
vErrors.push(err3);
}
errors++;
}
}
else {
const err4 = {instancePath:instancePath+"/name",schemaPath:"#/properties/name/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err4];
}
else {
vErrors.push(err4);
}
errors++;
}
}
if(data.redirect_uris !== undefined){
let data1 = data.redirect_uris;
if(Array.isArray(data1)){
if(data1.length < 1){
const err5 = {instancePath:instancePath+"/redirect_uris",schemaPath:"#/properties/redirect_uris/minItems",keyword:"minItems",params:{limit: 1},message:"must NOT have fewer than 1 items"};
if(vErrors === null){
vErrors = [err5];
}
else {
vErrors.push(err5);
}
errors++;
}
const len0 = data1.length;
for(let i0=0; i0<len0; i0++){
let data2 = data1[i0];
if(typeof data2 === "string"){
if(!(formats0.test(data2))){
const err6 = {instancePath:instancePath+"/redirect_uris/" + i0,schemaPath:"#/properties/redirect_uris/items/format",keyword:"format",params:{format: "uri"},message:"must match format \""+"uri"+"\""};
if(vErrors === null){
vErrors = [err6];
}
else {
vErrors.push(err6);
}
errors++;
}
}
else {
const err7 = {instancePath:instancePath+"/redirect_uris/" + i0,schemaPath:"#/properties/redirect_uris/items/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err7];
}
else {
vErrors.push(err7);
}
errors++;
}
}
}
else {
const err8 = {instancePath:instancePath+"/redirect_uris",schemaPath:"#/properties/redirect_uris/type",keyword:"type",params:{type: "array"},message:"must be array"};
if(vErrors === null){
vErrors = [err8];
}
else {
vErrors.push(err8);
}
errors++;
}
}
if(data.client_did !== undefined){
let data3 = data.client_did;
if(typeof data3 === "string"){
if(!pattern4.test(data3)){
const err9 = {instancePath:instancePath+"/client_did",schemaPath:"#/properties/client_did/pattern",keyword:"pattern",params:{pattern: "^did:dfos:[2346789acdefhknrtvz]{31}$"},message:"must match pattern \""+"^did:dfos:[2346789acdefhknrtvz]{31}$"+"\""};
if(vErrors === null){
vErrors = [err9];
}
else {
vErrors.push(err9);
}
errors++;
}
}
else {
const err10 = {instancePath:instancePath+"/client_did",schemaPath:"#/properties/client_did/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err10];
}
else {
vErrors.push(err10);
}
errors++;
}
}
if(data.identity_chain !== undefined){
let data4 = data.identity_chain;
if(Array.isArray(data4)){
if(data4.length > 100){
const err11 = {instancePath:instancePath+"/identity_chain",schemaPath:"#/properties/identity_chain/maxItems",keyword:"maxItems",params:{limit: 100},message:"must NOT have more than 100 items"};
if(vErrors === null){
vErrors = [err11];
}
else {
vErrors.push(err11);
}
errors++;
}
if(data4.length < 1){
const err12 = {instancePath:instancePath+"/identity_chain",schemaPath:"#/properties/identity_chain/minItems",keyword:"minItems",params:{limit: 1},message:"must NOT have fewer than 1 items"};
if(vErrors === null){
vErrors = [err12];
}
else {
vErrors.push(err12);
}
errors++;
}
const len1 = data4.length;
for(let i1=0; i1<len1; i1++){
let data5 = data4[i1];
if(typeof data5 === "string"){
if(func1(data5) < 1){
const err13 = {instancePath:instancePath+"/identity_chain/" + i1,schemaPath:"#/properties/identity_chain/items/minLength",keyword:"minLength",params:{limit: 1},message:"must NOT have fewer than 1 characters"};
if(vErrors === null){
vErrors = [err13];
}
else {
vErrors.push(err13);
}
errors++;
}
}
else {
const err14 = {instancePath:instancePath+"/identity_chain/" + i1,schemaPath:"#/properties/identity_chain/items/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err14];
}
else {
vErrors.push(err14);
}
errors++;
}
}
}
else {
const err15 = {instancePath:instancePath+"/identity_chain",schemaPath:"#/properties/identity_chain/type",keyword:"type",params:{type: "array"},message:"must be array"};
if(vErrors === null){
vErrors = [err15];
}
else {
vErrors.push(err15);
}
errors++;
}
}
if(data.identity_chain !== undefined){
if(data.client_did === undefined){
const err16 = {instancePath,schemaPath:"#/dependentRequired",keyword:"dependentRequired",params:{property: "identity_chain",
    missingProperty: "client_did",
    depsCount: 1,
    deps: "client_did"},message:"must have property client_did when property identity_chain is present"};
if(vErrors === null){
vErrors = [err16];
}
else {
vErrors.push(err16);
}
errors++;
}
}
}
else {
const err17 = {instancePath,schemaPath:"#/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err17];
}
else {
vErrors.push(err17);
}
errors++;
}
validate20.errors = vErrors;
return errors === 0;
}
validate20.evaluated = {"props":true,"dynamicProps":false,"dynamicItems":false};

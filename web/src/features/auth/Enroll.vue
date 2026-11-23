<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { NButton,NInput,NAlert } from 'naive-ui'
import {request} from '../../api/client'
import {useAuth,type Enrollment} from './store'
import AuthShell from './AuthShell.vue'
const auth=useAuth(),router=useRouter()
const raw=ref(''),invite=ref(''),uri=ref(''),expires=ref(''),password=ref(''),code=ref(''),codes=ref<string[]>([]),error=ref(''),busy=ref(false)
function accept(bundle:unknown){
 if(!bundle||typeof bundle!=='object')throw new Error('绑定资料格式不正确。')
 const v=bundle as Enrollment
 if(typeof v.invite_id!=='string'||v.invite_id.length!==43||typeof v.provisioning_uri!=='string'||v.provisioning_uri.length>2048||typeof v.expires!=='string')throw new Error('绑定资料格式不正确。')
 const u=new URL(v.provisioning_uri)
 if(u.protocol!=='otpauth:'||u.hostname!=='totp'||!u.searchParams.get('secret')||!Number.isFinite(Date.parse(v.expires))||Date.parse(v.expires)<=Date.now())throw new Error('绑定资料已过期或格式不正确。')
 invite.value=v.invite_id;uri.value=v.provisioning_uri;expires.value=v.expires;raw.value=''
}
function load(){error.value='';try{accept(JSON.parse(raw.value))}catch{error.value='绑定资料已过期或格式不正确，请向授权管理员获取新资料。'}finally{raw.value=''}}
const incoming=auth.enrollment;auth.enrollment=null
if(incoming){try{accept(incoming)}catch{error.value='恢复绑定资料已过期，请重新获取。'}}
// Fragments never reach HTTP servers; scrub before rendering and never persist.
if(location.hash){const fragment=location.hash.slice(1);history.replaceState(null,'',location.pathname);try{accept(JSON.parse(decodeURIComponent(fragment.startsWith('bundle=')?fragment.slice(7):fragment)))}catch{error.value='绑定链接格式不正确或已过期。'}}
async function submit(){busy.value=true;error.value='';try{const out=await request<{recovery_codes:string[]}>('/auth/enroll',{invite_id:invite.value,password:password.value,code:code.value});codes.value=out.recovery_codes;invite.value='';uri.value=''}catch(e){error.value=e instanceof Error?e.message:'绑定失败。'}finally{password.value='';code.value='';busy.value=false}}
function close(){codes.value=[];uri.value='';invite.value='';void router.replace('/login')}
</script>
<template><auth-shell><template v-if="codes.length"><h1>保存恢复码</h1><p class="muted">请将这些一次性恢复码保存在安全的位置。关闭后无法再次查看。</p><pre class="secret my-6" data-testid="recovery-codes">{{codes.join('\n')}}</pre><n-button type="primary" block @click="close">已保存，关闭并登录</n-button></template><template v-else><h1>绑定身份验证器</h1><p class="muted">使用授权管理员提供的一次性资料，将标准 TOTP 密钥导入身份验证器。</p><n-alert v-if="error" type="error" role="alert" class="error">{{error}}</n-alert><template v-if="!invite"><label class="field"><span class="field-label">一次性绑定资料</span><n-input v-model:value="raw" type="textarea" :input-props="{'aria-label':'一次性绑定资料',autocomplete:'off',spellcheck:false,maxlength:4096}"/></label><n-button type="primary" block @click="load">读取绑定资料</n-button></template><template v-else><div v-if="uri" class="my-5"><p class="muted">仅在此处展示的标准绑定 URI：</p><code class="secret" data-testid="provisioning-uri">{{uri}}</code><n-button text class="mt-3" @click="uri=''">隐藏绑定密钥</n-button></div><p class="text-xs muted">有效期至 {{new Date(expires).toLocaleString('zh-CN')}}</p><form @submit.prevent="submit"><label class="field"><span class="field-label">设置密码</span><n-input v-model:value="password" type="password" :input-props="{'aria-label':'设置密码',autocomplete:'new-password',minlength:15,maxlength:1024,required:true}"/></label><p class="text-xs muted">密码至少 15 个字符。</p><label class="field"><span class="field-label">动态验证码</span><n-input v-model:value="code" :input-props="{'aria-label':'动态验证码',autocomplete:'one-time-code',inputmode:'numeric',pattern:'[0-9]{6}',maxlength:6,required:true}"/></label><n-button attr-type="submit" type="primary" block :loading="busy" :disabled="busy">完成绑定</n-button></form></template><div class="actions"><router-link to="/login">返回登录</router-link></div></template></auth-shell></template>

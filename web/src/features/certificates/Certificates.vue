<script setup lang="ts">
import {ref,onMounted,onUnmounted} from 'vue';
import {useQueryClient} from '@tanstack/vue-query';
import Resources from './Resources.vue';
import {request} from '../../api/client';
import {permissions,message} from '../sites/data';
const {isAdmin}=permissions(),client=useQueryClient(),id=ref(''),cert=ref(''),key=ref(''),code=ref(''),busy=ref(false),error=ref(''),notice=ref(''),importForm=ref<HTMLFormElement>();
function clear(){
 key.value='';code.value='';cert.value='';
 // Clear live controls synchronously before the document can enter bfcache.
 importForm.value?.querySelectorAll<HTMLInputElement|HTMLTextAreaElement>('[data-import-secret]').forEach(field=>{field.value=''})
}
onMounted(()=>window.addEventListener('pagehide',clear));
onUnmounted(()=>{clear();window.removeEventListener('pagehide',clear)});
async function upload(){busy.value=true;error.value='';notice.value='';try{await request('/certificates/spec/'+id.value+'/import',{certificate_pem:cert.value,private_key_pem:key.value,totp_code:code.value});notice.value='导入已提交；请人工发布相应规格修订，并核对实际应用结果。';await client.invalidateQueries({queryKey:['pki-resources']})}catch(e){error.value=message(e)}finally{clear();busy.value=false}}
</script>
<template><section><h1>证书管理</h1><h2>准备与生效分别确认</h2><p class="muted">显式创建/启用资源授权后台准备；API 不执行 ACME 或网络检测。正常自动续期只更新兼容材料版本，真实生效需网关应用确认。失败和重试单独显示；禁用身份与吊销证书是不同操作。</p><Resources kind="spec"/><Resources kind="trust"/>
<section class="panel"><h2>Cloudflare Authenticated Origin Pulls</h2><p>这是独立第三方信任机制。导入 Cloudflare 官方或自有 AOP 信任包，核对证书用途、状态配置与实际入口验证结果；在 Cloudflare 控制台手动开启/配置对应域名的 Origin Pulls，并确认当前套餐和功能支持。此管理 API 不修改 Cloudflare 账号功能或套餐。仅导入不代表连接已通过验证。</p></section>
<form ref="importForm" v-if="isAdmin" class="panel" @submit.prevent="upload"><h2>手动导入证书材料</h2><p>仅允许 import 规格。替换已有证书必须先保存新规格修订并人工发布；不会自动续期。</p><p v-if="error" role="alert">{{error}}</p><p v-if="notice" role="status">{{notice}}</p><fieldset :disabled="busy"><label>导入规格 ID<input v-model="id" required></label><label>证书链 PEM<textarea data-import-secret v-model="cert" required/></label><label>私钥 PEM（仅提交）<textarea data-import-secret v-model="key" required autocomplete="off"/></label><label>导入动态验证码<input data-import-secret v-model="code" type="password" inputmode="numeric" maxlength="6" required autocomplete="off"></label><button>提交导入并清除秘密</button></fieldset></form></section></template>

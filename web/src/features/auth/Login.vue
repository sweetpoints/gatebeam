<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { NButton, NInput, NAlert } from 'naive-ui'
import { request } from '../../api/client'
import { useAuth } from './store'
import AuthShell from './AuthShell.vue'
const name=ref(''), password=ref(''), code=ref(''), challenge=ref(''), busy=ref(false), error=ref('')
const router=useRouter(), auth=useAuth()
async function submit(){busy.value=true;error.value='';try{
 if(!challenge.value){const out=await request<{challenge_id:string}>('/auth/login',{name:name.value,password:password.value});password.value='';challenge.value=out.challenge_id}
 else {await auth.finish(challenge.value,code.value);code.value='';challenge.value='';await router.replace('/')}
}catch(e){error.value=e instanceof Error?e.message:'登录失败。';code.value=''}finally{password.value='';busy.value=false}}
</script>
<template><auth-shell><p class="text-sm muted mb-3">管理控制台</p><h1>{{challenge?'验证您的身份':'欢迎回来'}}</h1><p class="muted">{{challenge?'输入身份验证器中的 6 位动态验证码。':'使用已完成绑定的账号安全登录。'}}</p><n-alert v-if="error" type="error" role="alert" class="error">{{error}}</n-alert><form @submit.prevent="submit"><template v-if="!challenge"><label class="field"><span class="field-label">账号</span><n-input v-model:value="name" :input-props="{'aria-label':'账号',id:'name',autocomplete:'username',required:true,maxlength:128}"/></label><label class="field"><span class="field-label">密码</span><n-input v-model:value="password" type="password" :input-props="{'aria-label':'密码',autocomplete:'current-password',required:true,maxlength:1024}"/></label></template><label v-else class="field"><span class="field-label">动态验证码</span><n-input v-model:value="code" :input-props="{'aria-label':'动态验证码',autocomplete:'one-time-code',inputmode:'numeric',pattern:'[0-9]{6}',required:true,maxlength:6}"/></label><n-button type="primary" attr-type="submit" block size="large" :loading="busy" :disabled="busy">{{challenge?'登录':'继续验证'}}</n-button></form><div class="actions"><router-link to="/enroll">首次绑定</router-link><router-link to="/recover">使用恢复码</router-link><n-button v-if="challenge" text @click="challenge='';code=''">返回账号登录</n-button></div></auth-shell></template>

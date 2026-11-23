<script setup lang="ts">
import {ref} from 'vue'
import {useRouter} from 'vue-router'
import {NButton,NInput,NAlert} from 'naive-ui'
import {request} from '../../api/client'
import {useAuth,type Enrollment} from './store'
import AuthShell from './AuthShell.vue'
const name=ref(''),password=ref(''),recovery=ref(''),error=ref(''),busy=ref(false)
const auth=useAuth(),router=useRouter()
async function submit(){busy.value=true;error.value='';try{const bundle=await request<Enrollment>('/auth/recover',{name:name.value,password:password.value,recovery_code:recovery.value});auth.clear();auth.enrollment=bundle;await router.replace('/enroll')}catch(e){error.value=e instanceof Error?e.message:'恢复失败。'}finally{password.value='';recovery.value='';busy.value=false}}
</script>
<template><auth-shell><h1>恢复账号访问</h1><p class="muted">使用密码和一个未使用的恢复码。恢复后需要重新绑定身份验证器，原会话将失效。</p><n-alert v-if="error" type="error" role="alert" class="error">{{error}}</n-alert><form @submit.prevent="submit"><label class="field"><span class="field-label">账号</span><n-input v-model:value="name" :input-props="{'aria-label':'账号',autocomplete:'username',maxlength:128,required:true}"/></label><label class="field"><span class="field-label">密码</span><n-input v-model:value="password" type="password" :input-props="{'aria-label':'密码',autocomplete:'current-password',maxlength:1024,required:true}"/></label><label class="field"><span class="field-label">恢复码</span><n-input v-model:value="recovery" type="password" :input-props="{'aria-label':'恢复码',autocomplete:'off',maxlength:43,required:true}"/></label><n-button attr-type="submit" type="primary" block :loading="busy" :disabled="busy">恢复并重新绑定</n-button></form><div class="actions"><router-link to="/login">返回登录</router-link></div></auth-shell></template>

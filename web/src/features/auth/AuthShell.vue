<script setup lang="ts">
import { ShieldCheck, ArrowUpRight } from '@lucide/vue'
</script>
<template><main class="auth-shell"><aside class="brand-panel"><div class="brand"><shield-check :size="28"/> GATEBEAM</div><div class="brand-story"><p class="text-sm tracking-widest opacity-65">安全入口 · 清晰掌控</p><h2 class="text-4xl leading-snug my-6">从可信身份开始。</h2><p class="leading-8 opacity-75">管理访问由密码与动态验证码共同保护。<br>每次会话都由服务端持续核验。</p></div><div class="brand-story text-xs opacity-60 flex gap-2 items-center"><arrow-up-right :size="14"/> 独立入口网关管理</div></aside><section class="auth-content"><div class="auth-card"><slot/></div></section></main></template>

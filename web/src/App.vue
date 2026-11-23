<script setup lang="ts">
import { NConfigProvider, NGlobalStyle, zhCN, dateZhCN } from 'naive-ui'
</script>
<template><n-config-provider :locale="zhCN" :date-locale="dateZhCN" :theme-overrides="{common:{primaryColor:'#176b5b',primaryColorHover:'#24826f',borderRadius:'10px'}}"><n-global-style/><router-view/></n-config-provider></template>

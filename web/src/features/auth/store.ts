import { defineStore } from 'pinia'
import { shallowRef } from 'vue'
import { APIError, csrfKey, request } from '../../api/client'
import { queryClient } from '../../api/query'
export interface Actor { user_id:string; role:string; credential_kind:string; credential_id:string; auth_version:number }
export interface Enrollment { invite_id:string; provisioning_uri:string; expires:string }
export const useAuth = defineStore('auth', () => {
  const actor = shallowRef<Actor | null>(null)
  // One-time authorized bundle exists only in memory between recovery and enrollment.
  const enrollment = shallowRef<Enrollment | null>(null)
  function clear() { actor.value = null; sessionStorage.removeItem(csrfKey); queryClient.clear() }
  async function refresh() {
    try { actor.value = await queryClient.fetchQuery({ queryKey:['session'], queryFn:() => request<Actor>('/auth/session') }); return true }
    catch (error) { actor.value=null; if(error instanceof APIError && error.status===401) { clear(); return false } throw error }
  }
  async function finish(challenge_id:string, code:string) {
    const out = await request<{csrf_token:string; actor:Actor}>('/auth/login/finish', {challenge_id,code})
    sessionStorage.setItem(csrfKey,out.csrf_token); actor.value=out.actor
  }
  async function logout() { await request('/auth/logout', {}); clear() }
  return { actor, enrollment, clear, refresh, finish, logout }
})

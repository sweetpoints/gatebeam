export class APIError extends Error {
  constructor(public status: number, public requestID: string, public code = '') {
    const text = status === 401 ? '认证失败或会话已失效，请重新登录。' : status === 403 ? '请求被拒绝，请检查权限及来源。' : status === 400 ? '资料格式不正确，请核对后重试。' : '服务暂时不可用，请稍后重试。'
    const detail:Record<string,string>={query_limit:'历史查询超限，请缩小时间、站点或扫描范围；未返回全量结果。',query_expired:'任务已到期或尚未完成，请刷新或重新提交。',revision_conflict:'草稿、已发布基线或域名已改变，请刷新并重新审阅。',resource_referenced:'资源仍被引用，请先检查引用关系。',materials_unavailable:'当前安全材料不可用。',invalid_request:'配置未通过服务端校验，请核对表单。',forbidden:'当前权限不足；共享资源要求全部引用站点授权。'}
    super(`${detail[code]||text}${requestID ? ` 请求编号：${requestID}` : ''}`)
  }
}
export const csrfKey = 'gatebeam.csrf'
export async function request<T>(path: string, body?: unknown, method?: 'POST'|'PUT'|'DELETE'): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    const csrf = sessionStorage.getItem(csrfKey)
    if (csrf) headers['X-CSRF-Token'] = csrf
  }
  let response: Response
  try {
    response = await fetch(path, { method: method || (body === undefined ? 'GET' : 'POST'), headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000) })
  } catch { throw new Error('无法连接服务，请检查网络后重试。') }
  if (!response.ok) { const error=await response.json().catch(()=>({})) as {code?:string}; throw new APIError(response.status, response.headers.get('X-Request-ID') || '', error.code || '') }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

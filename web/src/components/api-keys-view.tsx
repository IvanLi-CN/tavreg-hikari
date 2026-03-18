import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StatusBadge } from "@/components/status-badge";
import type { ApiKeyQuery, ApiKeyRecord } from "@/lib/app-types";
import { formatDate } from "@/lib/format";

function FilterField(props: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

export function ApiKeysView({
  apiKeys,
  query,
  onQueryChange,
}: {
  apiKeys: { rows: ApiKeyRecord[]; total: number };
  query: ApiKeyQuery;
  onQueryChange: (value: ApiKeyQuery) => void;
}) {
  const activeCount = apiKeys.rows.filter((row) => row.status === "active").length;
  const revokedCount = apiKeys.rows.filter((row) => row.status === "revoked").length;

  return (
    <Card>
      <CardHeader>
        <CardTitle>API Keys</CardTitle>
        <CardDescription>共 {apiKeys.total} 条 key 记录，默认展示前缀与遮罩值。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant="success">active · {activeCount}</Badge>
          <Badge variant="warning">revoked · {revokedCount}</Badge>
          <Badge variant="info">total · {apiKeys.total}</Badge>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <FilterField label="搜索">
            <Input
              name="api-key-query"
              value={query.q}
              onChange={(event) => onQueryChange({ ...query, q: event.target.value })}
              placeholder="邮箱或前缀"
            />
          </FilterField>
          <FilterField label="状态">
            <Select value={query.status || "__all__"} onValueChange={(value) => onQueryChange({ ...query, status: value === "__all__" ? "" : value })}>
              <SelectTrigger>
                <SelectValue placeholder="全部" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__all__">全部</SelectItem>
                <SelectItem value="active">active</SelectItem>
                <SelectItem value="revoked">revoked</SelectItem>
                <SelectItem value="unknown">unknown</SelectItem>
              </SelectContent>
            </Select>
          </FilterField>
        </div>

        {apiKeys.rows.length === 0 ? (
          <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
            还没有 API key 记录。
          </div>
        ) : (
          <>
            <div className="space-y-3 md:hidden">
              {apiKeys.rows.map((row) => (
                <article key={row.id} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="break-all text-sm font-medium text-white">{row.microsoftEmail}</div>
                      <div className="mt-1 text-sm text-slate-400">{row.apiKeyPrefix}</div>
                    </div>
                    <StatusBadge status={row.status} />
                  </div>
                  <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-slate-500">遮罩</dt>
                      <dd>{row.apiKeyMasked}</dd>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-slate-500">提取时间</dt>
                      <dd>{formatDate(row.extractedAt)}</dd>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-slate-500">最近验证</dt>
                      <dd>{formatDate(row.lastVerifiedAt)}</dd>
                    </div>
                  </dl>
                </article>
              ))}
            </div>
            <div className="hidden md:block">
              <Table className="min-w-[860px]">
                <TableHeader>
                  <TableRow>
                    <TableHead>账号</TableHead>
                    <TableHead>Key 前缀</TableHead>
                    <TableHead>Key 遮罩</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>提取时间</TableHead>
                    <TableHead>最近验证</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {apiKeys.rows.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell className="min-w-[15rem] whitespace-nowrap">{row.microsoftEmail}</TableCell>
                      <TableCell>{row.apiKeyPrefix}</TableCell>
                      <TableCell>{row.apiKeyMasked}</TableCell>
                      <TableCell><StatusBadge status={row.status} /></TableCell>
                      <TableCell>{formatDate(row.extractedAt)}</TableCell>
                      <TableCell>{formatDate(row.lastVerifiedAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

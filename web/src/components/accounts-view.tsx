import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/status-badge";
import type { AccountQuery, AccountRecord } from "@/lib/app-types";
import { formatDate } from "@/lib/format";

function FilterField(props: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

export function AccountsView({
  accounts,
  importContent,
  query,
  onImportContentChange,
  onImport,
  onQueryChange,
}: {
  accounts: { rows: AccountRecord[]; total: number };
  importContent: string;
  query: AccountQuery;
  onImportContentChange: (value: string) => void;
  onImport: () => void;
  onQueryChange: (value: AccountQuery) => void;
}) {
  const readyCount = accounts.rows.filter((row) => row.lastResultStatus === "ready").length;
  const linkedCount = accounts.rows.filter((row) => row.hasApiKey).length;
  const failedCount = accounts.rows.filter((row) => row.lastResultStatus === "failed").length;

  return (
    <section className="grid gap-4 xl:grid-cols-[minmax(22rem,0.56fr)_minmax(0,1.44fr)]">
      <Card>
        <CardHeader>
          <CardTitle>导入微软账号</CardTitle>
          <CardDescription>每行一个账号，格式固定为 <code>email,password</code>。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            name="account-import"
            className="min-h-72"
            placeholder="example@outlook.com,password123"
            value={importContent}
            onChange={(event) => onImportContentChange(event.target.value)}
          />
          <Button onClick={onImport} disabled={!importContent.trim()}>
            导入并去重
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>账号池</CardTitle>
          <CardDescription>共 {accounts.total} 条记录。已有关联 API key 的账号会被标记并跳过调度。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Badge variant="info">ready · {readyCount}</Badge>
            <Badge variant="success">linked · {linkedCount}</Badge>
            <Badge variant="danger">failed · {failedCount}</Badge>
          </div>
          <div className="grid gap-3 lg:grid-cols-3">
            <FilterField label="搜索">
              <Input
                name="account-query"
                value={query.q}
                onChange={(event) => onQueryChange({ ...query, q: event.target.value })}
                placeholder="邮箱"
              />
            </FilterField>
            <FilterField label="状态">
              <Select value={query.status || "__all__"} onValueChange={(value) => onQueryChange({ ...query, status: value === "__all__" ? "" : value })}>
                <SelectTrigger>
                  <SelectValue placeholder="全部" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">全部</SelectItem>
                  <SelectItem value="ready">ready</SelectItem>
                  <SelectItem value="running">running</SelectItem>
                  <SelectItem value="succeeded">succeeded</SelectItem>
                  <SelectItem value="failed">failed</SelectItem>
                  <SelectItem value="skipped_has_key">skipped_has_key</SelectItem>
                </SelectContent>
              </Select>
            </FilterField>
            <FilterField label="Has API Key">
              <Select value={query.hasApiKey || "__all__"} onValueChange={(value) => onQueryChange({ ...query, hasApiKey: value === "__all__" ? "" : value })}>
                <SelectTrigger>
                  <SelectValue placeholder="全部" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">全部</SelectItem>
                  <SelectItem value="true">true</SelectItem>
                  <SelectItem value="false">false</SelectItem>
                </SelectContent>
              </Select>
            </FilterField>
          </div>

          {accounts.rows.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
              还没有账号记录。
            </div>
          ) : (
            <>
              <div className="space-y-3 md:hidden">
                {accounts.rows.map((row) => (
                  <article key={row.id} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="break-all text-sm font-medium text-white">{row.microsoftEmail}</div>
                        <div className="mt-1 text-sm text-slate-400">{row.passwordMasked}</div>
                      </div>
                      {row.hasApiKey ? <StatusBadge status="active" /> : <StatusBadge status="no-key" />}
                    </div>
                    <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">最近状态</dt>
                        <dd><StatusBadge status={row.lastResultStatus} /></dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">导入时间</dt>
                        <dd>{formatDate(row.importedAt)}</dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">最近使用</dt>
                        <dd>{formatDate(row.lastUsedAt)}</dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">跳过原因</dt>
                        <dd>{row.skipReason || "—"}</dd>
                      </div>
                    </dl>
                  </article>
                ))}
              </div>
              <div className="hidden md:block">
                <Table className="min-w-[920px]">
                  <TableHeader>
                    <TableRow>
                      <TableHead>邮箱</TableHead>
                      <TableHead>密码</TableHead>
                      <TableHead>Has Key</TableHead>
                      <TableHead>最近状态</TableHead>
                      <TableHead>导入时间</TableHead>
                      <TableHead>最近使用</TableHead>
                      <TableHead>跳过原因</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {accounts.rows.map((row) => (
                      <TableRow key={row.id}>
                        <TableCell className="min-w-[15rem] whitespace-nowrap">{row.microsoftEmail}</TableCell>
                        <TableCell>{row.passwordMasked}</TableCell>
                        <TableCell>{row.hasApiKey ? <StatusBadge status="active" /> : <StatusBadge status="no-key" />}</TableCell>
                        <TableCell><StatusBadge status={row.lastResultStatus} /></TableCell>
                        <TableCell>{formatDate(row.importedAt)}</TableCell>
                        <TableCell>{formatDate(row.lastUsedAt)}</TableCell>
                        <TableCell className="min-w-[10rem]">{row.skipReason || "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

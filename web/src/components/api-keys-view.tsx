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
  return (
    <Card>
      <CardHeader>
        <CardTitle>API Keys</CardTitle>
        <CardDescription>共 {apiKeys.total} 条 key 记录，默认展示前缀与遮罩值。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
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

        <Table>
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
            {apiKeys.rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-slate-400">还没有 API key 记录。</TableCell>
              </TableRow>
            ) : (
              apiKeys.rows.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="break-all">{row.microsoftEmail}</TableCell>
                  <TableCell>{row.apiKeyPrefix}</TableCell>
                  <TableCell>{row.apiKeyMasked}</TableCell>
                  <TableCell><StatusBadge status={row.status} /></TableCell>
                  <TableCell>{formatDate(row.extractedAt)}</TableCell>
                  <TableCell>{formatDate(row.lastVerifiedAt)}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

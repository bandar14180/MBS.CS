"use client";

import { useEffect, useState } from "react";

import { ApiError, memberApi, type Member, type Role } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Button, Card, Empty, ErrorText, Input, Label, Select, Spinner } from "@/components/ui";

export default function TeamPage() {
  const { t } = useTranslation();
  const [members, setMembers] = useState<Member[] | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [denied, setDenied] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    try {
      setMembers(await memberApi.list());
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setDenied(true);
      setMembers([]);
    }
  }
  useEffect(() => {
    load();
    memberApi.roles().then(setRoles).catch(() => {});
  }, []);

  const roleNames = roles.length ? roles.map((r) => r.name) : ["owner", "admin", "member"];

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await memberApi.invite(email, role);
      setEmail("");
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function changeRole(m: Member, roleName: string) {
    try {
      await memberApi.updateRole(m.user_id, roleName);
      await load();
    } catch (e: any) {
      setError(e.message);
    }
  }
  async function remove(m: Member) {
    try {
      await memberApi.remove(m.user_id);
      await load();
    } catch (e: any) {
      setError(e.message);
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="mb-1 text-2xl font-semibold text-white">{t("team.title")}</h1>
      <p className="mb-6 text-sm text-slate-400">{t("team.subtitle")}</p>

      {denied ? (
        <Card>
          <Empty>{t("team.denied")}</Empty>
        </Card>
      ) : (
        <>
          <Card className="mb-6">
            <form onSubmit={invite} className="flex flex-wrap items-end gap-3">
              <div className="min-w-[15rem] flex-1">
                <Label>{t("team.inviteEmail")}</Label>
                <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="teammate@company.com" required dir="ltr" />
              </div>
              <div>
                <Label>{t("team.role")}</Label>
                <Select value={role} onChange={(e) => setRole(e.target.value)}>
                  {roleNames.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </Select>
              </div>
              <Button type="submit" disabled={busy || !email.trim()}>
                {t("team.invite")}
              </Button>
            </form>
            <ErrorText>{error}</ErrorText>
          </Card>

          {members === null ? (
            <Spinner />
          ) : members.length === 0 ? (
            <Card><Empty>{t("team.empty")}</Empty></Card>
          ) : (
            <div className="space-y-2">
              {members.map((m) => (
                <Card key={m.id} className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-slate-100">{m.full_name}</div>
                    <div className="text-xs text-slate-500" dir="ltr">{m.email}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Select value={m.role_name} onChange={(e) => changeRole(m, e.target.value)}>
                      {roleNames.map((r) => (
                        <option key={r} value={r}>{r}</option>
                      ))}
                    </Select>
                    <Button variant="danger" onClick={() => remove(m)}>
                      {t("team.remove")}
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

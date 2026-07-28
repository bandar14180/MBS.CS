"use client";

import { useEffect, useState } from "react";

import { ApiError, apiKeyApi, type ApiKey } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Button, Card, Empty, ErrorText, Input, Label, Spinner } from "@/components/ui";

export default function ApiKeysPage() {
  const { t } = useTranslation();
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [denied, setDenied] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function load() {
    try {
      setKeys(await apiKeyApi.list());
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setDenied(true);
      setKeys([]);
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const created = await apiKeyApi.create(name);
      setNewSecret(created.secret);
      setName("");
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(k: ApiKey) {
    try {
      await apiKeyApi.revoke(k.id);
      await load();
    } catch (e: any) {
      setError(e.message);
    }
  }

  function copy() {
    if (!newSecret) return;
    navigator.clipboard?.writeText(newSecret);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="mb-1 text-2xl font-semibold text-white">{t("apiKeys.title")}</h1>
      <p className="mb-6 text-sm text-slate-400">{t("apiKeys.subtitle")}</p>

      {denied ? (
        <Card>
          <Empty>{t("apiKeys.denied")}</Empty>
        </Card>
      ) : (
        <>
          {newSecret && (
            <Card className="mb-6 border-accent-cyan/40 bg-accent-cyan/5">
              <div className="text-sm font-medium text-white">{t("apiKeys.secretOnce")}</div>
              <div className="mt-2 flex items-center gap-2">
                <code className="flex-1 overflow-x-auto rounded-md bg-black/40 px-3 py-2 font-mono text-xs text-accent-cyan" dir="ltr">
                  {newSecret}
                </code>
                <Button variant="secondary" onClick={copy}>
                  {copied ? t("apiKeys.copied") : t("apiKeys.copy")}
                </Button>
              </div>
              <button onClick={() => setNewSecret(null)} className="mt-2 text-xs text-slate-500 hover:text-slate-300">
                {t("apiKeys.dismiss")}
              </button>
            </Card>
          )}

          <Card className="mb-6">
            <form onSubmit={create} className="flex flex-wrap items-end gap-3">
              <div className="min-w-[16rem] flex-1">
                <Label>{t("apiKeys.name")}</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="CI pipeline" required />
              </div>
              <Button type="submit" disabled={busy || !name.trim()}>
                {t("apiKeys.create")}
              </Button>
            </form>
            <ErrorText>{error}</ErrorText>
          </Card>

          {keys === null ? (
            <Spinner />
          ) : keys.length === 0 ? (
            <Card>
              <Empty>{t("apiKeys.empty")}</Empty>
            </Card>
          ) : (
            <div className="space-y-2">
              {keys.map((k) => (
                <Card key={k.id} className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-slate-100">
                      {k.name}
                      {k.revoked && <span className="ms-2 text-xs text-rose-400">({t("apiKeys.revoked")})</span>}
                    </div>
                    <div className="mt-0.5 text-xs text-slate-500">
                      <code className="font-mono text-slate-400" dir="ltr">{k.prefix}…</code> ·{" "}
                      {k.last_used_at
                        ? `${t("apiKeys.lastUsed")}: ${new Date(k.last_used_at).toLocaleString()}`
                        : t("apiKeys.neverUsed")}
                    </div>
                  </div>
                  {!k.revoked && (
                    <Button variant="danger" onClick={() => revoke(k)}>
                      {t("apiKeys.revoke")}
                    </Button>
                  )}
                </Card>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

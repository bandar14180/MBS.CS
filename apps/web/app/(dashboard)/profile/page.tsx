"use client";

import { useEffect, useState } from "react";

import { authApi, profileApi, type User } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Button, Card, ErrorText, Input, Label, Spinner } from "@/components/ui";

export default function ProfilePage() {
  const { t } = useTranslation();
  const [user, setUser] = useState<User | null>(null);
  const [fullName, setFullName] = useState("");
  const [savedName, setSavedName] = useState(false);
  const [nameBusy, setNameBusy] = useState(false);
  const [nameErr, setNameErr] = useState("");

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [pwBusy, setPwBusy] = useState(false);
  const [pwErr, setPwErr] = useState("");
  const [pwOk, setPwOk] = useState(false);

  useEffect(() => {
    authApi.me().then((u) => {
      setUser(u);
      setFullName(u.full_name);
    });
  }, []);

  async function saveName(e: React.FormEvent) {
    e.preventDefault();
    setNameBusy(true);
    setNameErr("");
    setSavedName(false);
    try {
      const u = await profileApi.update(fullName);
      setUser(u);
      setSavedName(true);
    } catch (e: any) {
      setNameErr(e.message);
    } finally {
      setNameBusy(false);
    }
  }

  async function changePw(e: React.FormEvent) {
    e.preventDefault();
    setPwBusy(true);
    setPwErr("");
    setPwOk(false);
    try {
      await profileApi.changePassword(current, next);
      setCurrent("");
      setNext("");
      setPwOk(true);
    } catch (e: any) {
      setPwErr(e.message);
    } finally {
      setPwBusy(false);
    }
  }

  if (!user) return <Spinner />;

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="mb-6 text-2xl font-semibold text-white">{t("profile.title")}</h1>

      <Card className="mb-6">
        <form onSubmit={saveName} className="space-y-4">
          <div>
            <Label>{t("profile.email")}</Label>
            <Input value={user.email} disabled dir="ltr" />
          </div>
          <div>
            <Label>{t("profile.fullName")}</Label>
            <Input value={fullName} onChange={(e) => setFullName(e.target.value)} required />
          </div>
          <ErrorText>{nameErr}</ErrorText>
          <div className="flex items-center gap-3">
            <Button type="submit" disabled={nameBusy}>
              {t("profile.save")}
            </Button>
            {savedName && <span className="text-sm text-emerald-400">{t("profile.saved")}</span>}
          </div>
        </form>
      </Card>

      <Card>
        <h2 className="mb-4 font-medium text-white">{t("profile.changePassword")}</h2>
        <form onSubmit={changePw} className="space-y-4">
          <div>
            <Label>{t("profile.currentPassword")}</Label>
            <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </div>
          <div>
            <Label>{t("profile.newPassword")}</Label>
            <Input type="password" minLength={8} value={next} onChange={(e) => setNext(e.target.value)} required />
          </div>
          <ErrorText>{pwErr}</ErrorText>
          <div className="flex items-center gap-3">
            <Button type="submit" disabled={pwBusy}>
              {t("profile.updatePassword")}
            </Button>
            {pwOk && <span className="text-sm text-emerald-400">{t("profile.passwordChanged")}</span>}
          </div>
        </form>
      </Card>
    </div>
  );
}

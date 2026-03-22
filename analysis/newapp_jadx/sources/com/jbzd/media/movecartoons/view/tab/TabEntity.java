package com.jbzd.media.movecartoons.view.tab;

import p005b.p187j.p188a.p189d.InterfaceC1878a;

/* loaded from: classes2.dex */
public class TabEntity implements InterfaceC1878a {
    public int selectedIcon;
    public String title;
    public int unSelectedIcon;

    public TabEntity(String str, int i2, int i3) {
        this.title = str;
        this.selectedIcon = i2;
        this.unSelectedIcon = i3;
    }

    @Override // p005b.p187j.p188a.p189d.InterfaceC1878a
    public int getTabSelectedIcon() {
        return this.selectedIcon;
    }

    @Override // p005b.p187j.p188a.p189d.InterfaceC1878a
    public String getTabTitle() {
        return this.title;
    }

    @Override // p005b.p187j.p188a.p189d.InterfaceC1878a
    public int getTabUnselectedIcon() {
        return this.unSelectedIcon;
    }
}

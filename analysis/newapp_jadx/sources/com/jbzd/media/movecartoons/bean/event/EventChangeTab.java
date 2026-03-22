package com.jbzd.media.movecartoons.bean.event;

import java.io.Serializable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\b\t\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\b\u001a\u00020\u0002\u0012\u0006\u0010\t\u001a\u00020\u0005¢\u0006\u0004\b\u0017\u0010\u0018J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0006\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J$\u0010\n\u001a\u00020\u00002\b\b\u0002\u0010\b\u001a\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\u0005HÆ\u0001¢\u0006\u0004\b\n\u0010\u000bJ\u0010\u0010\f\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\f\u0010\u0004J\u0010\u0010\r\u001a\u00020\u0005HÖ\u0001¢\u0006\u0004\b\r\u0010\u0007J\u001a\u0010\u0011\u001a\u00020\u00102\b\u0010\u000f\u001a\u0004\u0018\u00010\u000eHÖ\u0003¢\u0006\u0004\b\u0011\u0010\u0012R\u0019\u0010\t\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\u0013\u001a\u0004\b\u0014\u0010\u0007R\u0019\u0010\b\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\u0015\u001a\u0004\b\u0016\u0010\u0004¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/event/EventChangeTab;", "Ljava/io/Serializable;", "", "component1", "()Ljava/lang/String;", "", "component2", "()I", "tabId", "tabIndex", "copy", "(Ljava/lang/String;I)Lcom/jbzd/media/movecartoons/bean/event/EventChangeTab;", "toString", "hashCode", "", "other", "", "equals", "(Ljava/lang/Object;)Z", "I", "getTabIndex", "Ljava/lang/String;", "getTabId", "<init>", "(Ljava/lang/String;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class EventChangeTab implements Serializable {

    @NotNull
    private final String tabId;
    private final int tabIndex;

    public EventChangeTab(@NotNull String tabId, int i2) {
        Intrinsics.checkNotNullParameter(tabId, "tabId");
        this.tabId = tabId;
        this.tabIndex = i2;
    }

    public static /* synthetic */ EventChangeTab copy$default(EventChangeTab eventChangeTab, String str, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            str = eventChangeTab.tabId;
        }
        if ((i3 & 2) != 0) {
            i2 = eventChangeTab.tabIndex;
        }
        return eventChangeTab.copy(str, i2);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getTabId() {
        return this.tabId;
    }

    /* renamed from: component2, reason: from getter */
    public final int getTabIndex() {
        return this.tabIndex;
    }

    @NotNull
    public final EventChangeTab copy(@NotNull String tabId, int tabIndex) {
        Intrinsics.checkNotNullParameter(tabId, "tabId");
        return new EventChangeTab(tabId, tabIndex);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof EventChangeTab)) {
            return false;
        }
        EventChangeTab eventChangeTab = (EventChangeTab) other;
        return Intrinsics.areEqual(this.tabId, eventChangeTab.tabId) && this.tabIndex == eventChangeTab.tabIndex;
    }

    @NotNull
    public final String getTabId() {
        return this.tabId;
    }

    public final int getTabIndex() {
        return this.tabIndex;
    }

    public int hashCode() {
        return (this.tabId.hashCode() * 31) + this.tabIndex;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("EventChangeTab(tabId=");
        m586H.append(this.tabId);
        m586H.append(", tabIndex=");
        return C1499a.m579A(m586H, this.tabIndex, ')');
    }
}

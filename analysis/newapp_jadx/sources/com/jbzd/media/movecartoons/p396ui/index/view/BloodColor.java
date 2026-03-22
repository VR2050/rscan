package com.jbzd.media.movecartoons.p396ui.index.view;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0005"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/view/BloodColor;", "", "", "setBloodColor", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public interface BloodColor {

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {}, m5311d2 = {}, m5312k = 3, m5313mv = {1, 5, 1})
    public static final class DefaultImpls {
        public static void setBloodColor(@NotNull BloodColor bloodColor) {
            Intrinsics.checkNotNullParameter(bloodColor, "this");
        }
    }

    void setBloodColor();
}

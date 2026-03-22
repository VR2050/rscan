package p005b.p006a.p007a.p008a.p013o;

import androidx.annotation.ColorRes;
import androidx.annotation.DrawableRes;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.a.a.a.o.b */
/* loaded from: classes2.dex */
public final class C0908b {

    /* renamed from: a */
    public final int f359a;

    /* renamed from: b */
    @NotNull
    public final String f360b;

    /* renamed from: c */
    @NotNull
    public final String f361c;

    /* renamed from: d */
    public final int f362d;

    /* renamed from: e */
    @Nullable
    public final Function0<Unit> f363e;

    public C0908b(@DrawableRes int i2, @NotNull String name, @NotNull String tips, @ColorRes int i3, @Nullable Function0<Unit> function0) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(tips, "tips");
        this.f359a = i2;
        this.f360b = name;
        this.f361c = tips;
        this.f362d = i3;
        this.f363e = function0;
    }

    public /* synthetic */ C0908b(int i2, String str, String str2, int i3, Function0 function0, int i4) {
        this(i2, str, (i4 & 4) != 0 ? "" : str2, (i4 & 8) != 0 ? 0 : i3, (i4 & 16) != 0 ? null : function0);
    }
}

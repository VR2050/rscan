package p458k.p459p0.p460d;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.C4381g0;
import p458k.C4389k0;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

/* renamed from: k.p0.d.d */
/* loaded from: classes3.dex */
public final class C4405d {

    /* renamed from: a */
    @Nullable
    public final C4381g0 f11568a;

    /* renamed from: b */
    @Nullable
    public final C4389k0 f11569b;

    public C4405d(@Nullable C4381g0 c4381g0, @Nullable C4389k0 c4389k0) {
        this.f11568a = c4381g0;
        this.f11569b = c4389k0;
    }

    /* renamed from: a */
    public static final boolean m5045a(@NotNull C4389k0 response, @NotNull C4381g0 request) {
        Intrinsics.checkParameterIsNotNull(response, "response");
        Intrinsics.checkParameterIsNotNull(request, "request");
        int i2 = response.f11488h;
        if (i2 != 200 && i2 != 410 && i2 != 414 && i2 != 501 && i2 != 203 && i2 != 204) {
            if (i2 != 307) {
                if (i2 != 308 && i2 != 404 && i2 != 405) {
                    switch (i2) {
                        case IjkMediaCodecInfo.RANK_SECURE /* 300 */:
                        case 301:
                            break;
                        case 302:
                            break;
                        default:
                            return false;
                    }
                }
            }
            if (C4389k0.m4987d(response, "Expires", null, 2) == null && response.m4988b().f11411d == -1 && !response.m4988b().f11414g && !response.m4988b().f11413f) {
                return false;
            }
        }
        return (response.m4988b().f11410c || request.m4969a().f11410c) ? false : true;
    }
}

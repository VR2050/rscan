package p411e.p412a.p413a.p417v1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.internal.ThreadConfig;
import java.util.concurrent.Executor;

/* renamed from: e.a.a.v1.c */
/* loaded from: classes.dex */
public final /* synthetic */ class C4287c {
    @NonNull
    /* renamed from: a */
    public static Executor m4892a(ThreadConfig _this) {
        return (Executor) _this.retrieveOption(ThreadConfig.OPTION_BACKGROUND_EXECUTOR);
    }

    @Nullable
    /* renamed from: b */
    public static Executor m4893b(@Nullable ThreadConfig _this, Executor executor) {
        return (Executor) _this.retrieveOption(ThreadConfig.OPTION_BACKGROUND_EXECUTOR, executor);
    }
}

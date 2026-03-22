package p411e.p412a.p413a.p417v1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.internal.IoConfig;
import java.util.concurrent.Executor;

/* renamed from: e.a.a.v1.a */
/* loaded from: classes.dex */
public final /* synthetic */ class C4285a {
    @NonNull
    /* renamed from: a */
    public static Executor m4886a(IoConfig _this) {
        return (Executor) _this.retrieveOption(IoConfig.OPTION_IO_EXECUTOR);
    }

    @Nullable
    /* renamed from: b */
    public static Executor m4887b(@Nullable IoConfig _this, Executor executor) {
        return (Executor) _this.retrieveOption(IoConfig.OPTION_IO_EXECUTOR, executor);
    }
}

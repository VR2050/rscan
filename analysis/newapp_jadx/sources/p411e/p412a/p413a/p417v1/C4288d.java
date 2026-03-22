package p411e.p412a.p413a.p417v1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.UseCase;
import androidx.camera.core.internal.UseCaseEventConfig;

/* renamed from: e.a.a.v1.d */
/* loaded from: classes.dex */
public final /* synthetic */ class C4288d {
    @NonNull
    /* renamed from: a */
    public static UseCase.EventCallback m4894a(UseCaseEventConfig _this) {
        return (UseCase.EventCallback) _this.retrieveOption(UseCaseEventConfig.OPTION_USE_CASE_EVENT_CALLBACK);
    }

    @Nullable
    /* renamed from: b */
    public static UseCase.EventCallback m4895b(@Nullable UseCaseEventConfig _this, UseCase.EventCallback eventCallback) {
        return (UseCase.EventCallback) _this.retrieveOption(UseCaseEventConfig.OPTION_USE_CASE_EVENT_CALLBACK, eventCallback);
    }
}

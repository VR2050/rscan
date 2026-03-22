package android.view;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import androidx.annotation.MainThread;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a&\u0010\u0004\u001a\b\u0012\u0004\u0012\u00028\u00000\u0003\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u0002H\u0087\b¢\u0006\u0004\b\u0004\u0010\u0005¨\u0006\u0006"}, m5311d2 = {"Landroidx/navigation/NavArgs;", "Args", "Landroid/app/Activity;", "Landroidx/navigation/NavArgsLazy;", "navArgs", "(Landroid/app/Activity;)Landroidx/navigation/NavArgsLazy;", "navigation-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class ActivityNavArgsLazyKt {
    @MainThread
    @NotNull
    public static final /* synthetic */ <Args extends NavArgs> NavArgsLazy<Args> navArgs(@NotNull final Activity navArgs) {
        Intrinsics.checkParameterIsNotNull(navArgs, "$this$navArgs");
        Intrinsics.reifiedOperationMarker(4, "Args");
        return new NavArgsLazy<>(Reflection.getOrCreateKotlinClass(NavArgs.class), new Function0<Bundle>() { // from class: androidx.navigation.ActivityNavArgsLazyKt$navArgs$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Bundle invoke() {
                Intent intent = navArgs.getIntent();
                if (intent == null) {
                    StringBuilder m586H = C1499a.m586H("Activity ");
                    m586H.append(navArgs);
                    m586H.append(" has a null Intent");
                    throw new IllegalStateException(m586H.toString());
                }
                Bundle extras = intent.getExtras();
                if (extras != null) {
                    return extras;
                }
                StringBuilder m586H2 = C1499a.m586H("Activity ");
                m586H2.append(navArgs);
                m586H2.append(" has null extras in ");
                m586H2.append(intent);
                throw new IllegalStateException(m586H2.toString());
            }
        });
    }
}

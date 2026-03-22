package androidx.fragment.app;

import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\b\u001a7\u0010\b\u001a\u00020\u0005*\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00012\u0017\u0010\u0007\u001a\u0013\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u00050\u0003¢\u0006\u0002\b\u0006H\u0086\b¢\u0006\u0004\b\b\u0010\t\u001a7\u0010\n\u001a\u00020\u0005*\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00012\u0017\u0010\u0007\u001a\u0013\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u00050\u0003¢\u0006\u0002\b\u0006H\u0086\b¢\u0006\u0004\b\n\u0010\t\u001aA\u0010\f\u001a\u00020\u0005*\u00020\u00002\b\b\u0002\u0010\u000b\u001a\u00020\u00012\b\b\u0002\u0010\u0002\u001a\u00020\u00012\u0017\u0010\u0007\u001a\u0013\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u00050\u0003¢\u0006\u0002\b\u0006H\u0087\b¢\u0006\u0004\b\f\u0010\r¨\u0006\u000e"}, m5311d2 = {"Landroidx/fragment/app/FragmentManager;", "", "allowStateLoss", "Lkotlin/Function1;", "Landroidx/fragment/app/FragmentTransaction;", "", "Lkotlin/ExtensionFunctionType;", "body", "commit", "(Landroidx/fragment/app/FragmentManager;ZLkotlin/jvm/functions/Function1;)V", "commitNow", "now", "transaction", "(Landroidx/fragment/app/FragmentManager;ZZLkotlin/jvm/functions/Function1;)V", "fragment-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class FragmentManagerKt {
    public static final void commit(@NotNull FragmentManager commit, boolean z, @NotNull Function1<? super FragmentTransaction, Unit> body) {
        Intrinsics.checkParameterIsNotNull(commit, "$this$commit");
        Intrinsics.checkParameterIsNotNull(body, "body");
        FragmentTransaction beginTransaction = commit.beginTransaction();
        Intrinsics.checkExpressionValueIsNotNull(beginTransaction, "beginTransaction()");
        body.invoke(beginTransaction);
        if (z) {
            beginTransaction.commitAllowingStateLoss();
        } else {
            beginTransaction.commit();
        }
    }

    public static /* synthetic */ void commit$default(FragmentManager commit, boolean z, Function1 body, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = false;
        }
        Intrinsics.checkParameterIsNotNull(commit, "$this$commit");
        Intrinsics.checkParameterIsNotNull(body, "body");
        FragmentTransaction beginTransaction = commit.beginTransaction();
        Intrinsics.checkExpressionValueIsNotNull(beginTransaction, "beginTransaction()");
        body.invoke(beginTransaction);
        if (z) {
            beginTransaction.commitAllowingStateLoss();
        } else {
            beginTransaction.commit();
        }
    }

    public static final void commitNow(@NotNull FragmentManager commitNow, boolean z, @NotNull Function1<? super FragmentTransaction, Unit> body) {
        Intrinsics.checkParameterIsNotNull(commitNow, "$this$commitNow");
        Intrinsics.checkParameterIsNotNull(body, "body");
        FragmentTransaction beginTransaction = commitNow.beginTransaction();
        Intrinsics.checkExpressionValueIsNotNull(beginTransaction, "beginTransaction()");
        body.invoke(beginTransaction);
        if (z) {
            beginTransaction.commitNowAllowingStateLoss();
        } else {
            beginTransaction.commitNow();
        }
    }

    public static /* synthetic */ void commitNow$default(FragmentManager commitNow, boolean z, Function1 body, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = false;
        }
        Intrinsics.checkParameterIsNotNull(commitNow, "$this$commitNow");
        Intrinsics.checkParameterIsNotNull(body, "body");
        FragmentTransaction beginTransaction = commitNow.beginTransaction();
        Intrinsics.checkExpressionValueIsNotNull(beginTransaction, "beginTransaction()");
        body.invoke(beginTransaction);
        if (z) {
            beginTransaction.commitNowAllowingStateLoss();
        } else {
            beginTransaction.commitNow();
        }
    }

    @Deprecated(message = "Use commit { .. } or commitNow { .. } extensions")
    public static final void transaction(@NotNull FragmentManager transaction, boolean z, boolean z2, @NotNull Function1<? super FragmentTransaction, Unit> body) {
        Intrinsics.checkParameterIsNotNull(transaction, "$this$transaction");
        Intrinsics.checkParameterIsNotNull(body, "body");
        FragmentTransaction beginTransaction = transaction.beginTransaction();
        Intrinsics.checkExpressionValueIsNotNull(beginTransaction, "beginTransaction()");
        body.invoke(beginTransaction);
        if (z) {
            if (z2) {
                beginTransaction.commitNowAllowingStateLoss();
                return;
            } else {
                beginTransaction.commitNow();
                return;
            }
        }
        if (z2) {
            beginTransaction.commitAllowingStateLoss();
        } else {
            beginTransaction.commit();
        }
    }

    public static /* synthetic */ void transaction$default(FragmentManager transaction, boolean z, boolean z2, Function1 body, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = false;
        }
        if ((i2 & 2) != 0) {
            z2 = false;
        }
        Intrinsics.checkParameterIsNotNull(transaction, "$this$transaction");
        Intrinsics.checkParameterIsNotNull(body, "body");
        FragmentTransaction beginTransaction = transaction.beginTransaction();
        Intrinsics.checkExpressionValueIsNotNull(beginTransaction, "beginTransaction()");
        body.invoke(beginTransaction);
        if (z) {
            if (z2) {
                beginTransaction.commitNowAllowingStateLoss();
                return;
            } else {
                beginTransaction.commitNow();
                return;
            }
        }
        if (z2) {
            beginTransaction.commitAllowingStateLoss();
        } else {
            beginTransaction.commit();
        }
    }
}

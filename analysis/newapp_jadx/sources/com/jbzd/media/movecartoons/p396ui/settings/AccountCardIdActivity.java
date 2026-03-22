package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.util.Pair;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.ViewKt;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.databinding.ActAccountCardidBinding;
import com.jbzd.media.movecartoons.p396ui.settings.AccountCardIdActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p139f.p140a.p142b.C1537g;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\u0007¢\u0006\u0004\b\u0018\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J2\u0010\f\u001a\u00020\u00032!\u0010\u000b\u001a\u001d\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0004\u0012\u00020\u00030\u0006H\u0002¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u000e\u0010\u0005J\u000f\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0017\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/AccountCardIdActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActAccountCardidBinding;", "", "showMsg", "()V", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "pass", "resultBlock", "permissionCheck", "(Lkotlin/jvm/functions/Function1;)V", "bindEvent", "", "getTopBarTitle", "()Ljava/lang/String;", "Landroid/widget/TextView;", "tv_appname$delegate", "Lkotlin/Lazy;", "getTv_appname", "()Landroid/widget/TextView;", "tv_appname", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AccountCardIdActivity extends BaseBindingActivity<ActAccountCardidBinding> {

    /* renamed from: tv_appname$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_appname = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.settings.AccountCardIdActivity$tv_appname$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) AccountCardIdActivity.this.findViewById(R.id.tv_appname);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* JADX INFO: Access modifiers changed from: private */
    public final void permissionCheck(final Function1<? super Boolean, Unit> resultBlock) {
        Pair<List<String>, List<String>> m696b = C1537g.m696b("android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE");
        boolean z = false;
        if (((List) m696b.second).isEmpty()) {
            Iterator it = ((List) m696b.first).iterator();
            while (true) {
                if (!it.hasNext()) {
                    z = true;
                    break;
                } else if (!C1537g.m697c((String) it.next())) {
                    break;
                }
            }
        }
        if (z) {
            resultBlock.invoke(Boolean.TRUE);
            return;
        }
        C1537g c1537g = new C1537g("android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE");
        c1537g.f1739f = new C1537g.d() { // from class: b.a.a.a.t.n.a
            @Override // p005b.p139f.p140a.p142b.C1537g.d
            /* renamed from: a */
            public final void mo300a(boolean z2, List list, List list2, List list3) {
                AccountCardIdActivity.m5996permissionCheck$lambda1(Function1.this, z2, list, list2, list3);
            }
        };
        c1537g.m700e();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: permissionCheck$lambda-1, reason: not valid java name */
    public static final void m5996permissionCheck$lambda1(Function1 resultBlock, boolean z, List noName_1, List noName_2, List noName_3) {
        Intrinsics.checkNotNullParameter(resultBlock, "$resultBlock");
        Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
        Intrinsics.checkNotNullParameter(noName_2, "$noName_2");
        Intrinsics.checkNotNullParameter(noName_3, "$noName_3");
        resultBlock.invoke(Boolean.valueOf(z));
    }

    private final void showMsg() {
        MyApp myApp = MyApp.f9891f;
        String str = MyApp.f9892g.account_slat;
        if (str == null) {
            return;
        }
        bodyBinding(new Function1<ActAccountCardidBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AccountCardIdActivity$showMsg$1$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActAccountCardidBinding actAccountCardidBinding) {
                invoke2(actAccountCardidBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActAccountCardidBinding bodyBinding) {
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                TextView textView = bodyBinding.tvNickName;
                MyApp myApp2 = MyApp.f9891f;
                textView.setText(MyApp.f9892g.nickname);
                bodyBinding.tvUserId.setText(MyApp.f9892g.user_id);
                bodyBinding.tvInviteCode.setText(MyApp.f9892g.username);
                bodyBinding.tvInviteCode.setText(MyApp.f9892g.username);
            }
        });
        Bitmap m2410M = C2354n.m2410M(str, C2354n.m2425R(this, 200.0f), C2354n.m2425R(this, 200.0f));
        if (m2410M != null) {
            getBodyBinding().ivQrcodeCardid.setImageBitmap(m2410M);
            C2354n.m2374A(getBodyBinding().btnSaveCardid, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AccountCardIdActivity$showMsg$1$2
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                    invoke2(textView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull TextView it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    final AccountCardIdActivity accountCardIdActivity = AccountCardIdActivity.this;
                    accountCardIdActivity.permissionCheck(new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AccountCardIdActivity$showMsg$1$2.1
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                            invoke(bool.booleanValue());
                            return Unit.INSTANCE;
                        }

                        public final void invoke(boolean z) {
                            ActAccountCardidBinding bodyBinding;
                            if (!z) {
                                C4325a.m4899b(AccountCardIdActivity.this, "没有权限").show();
                                return;
                            }
                            AccountCardIdActivity accountCardIdActivity2 = AccountCardIdActivity.this;
                            bodyBinding = accountCardIdActivity2.getBodyBinding();
                            ConstraintLayout constraintLayout = bodyBinding.llCardInfo;
                            Intrinsics.checkNotNullExpressionValue(constraintLayout, "bodyBinding.llCardInfo");
                            C2354n.m2523v1(accountCardIdActivity2, ViewKt.drawToBitmap$default(constraintLayout, null, 1, null), AccountCardIdActivity.this.getString(R.string.account_certificate));
                            C4325a.m4902e(AccountCardIdActivity.this, "保存成功").show();
                        }
                    });
                }
            }, 1);
        } else {
            C2354n.m2374A(getBodyBinding().btnSaveCardid, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AccountCardIdActivity$showMsg$1$3
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                    invoke2(textView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull TextView it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    C2354n.m2449Z("二维码不存在");
                }
            }, 1);
        }
        getBodyBinding().tvSiteUrl.setText(getString(R.string.official_address, new Object[]{MyApp.m4185f().site_url}));
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        String str;
        TextView tv_appname = getTv_appname();
        Intrinsics.checkNotNullParameter(this, "context");
        try {
            PackageManager packageManager = getPackageManager();
            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
            str = (String) packageManager.getApplicationLabel(applicationInfo);
        } catch (PackageManager.NameNotFoundException unused) {
            str = "";
        }
        tv_appname.setText(Intrinsics.stringPlus(str, "官方平台"));
        showMsg();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.account_credentials);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.account_credentials)");
        return string;
    }

    @NotNull
    public final TextView getTv_appname() {
        return (TextView) this.tv_appname.getValue();
    }
}

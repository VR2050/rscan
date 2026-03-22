package com.jbzd.media.movecartoons.p396ui.mine;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Looper;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.constraintlayout.widget.Group;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.Observer;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import com.drake.brv.annotaion.DividerOrientation;
import com.google.android.material.imageview.ShapeableImageView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.event.EventChangeTab;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.jbzd.media.movecartoons.databinding.FragMineBinding;
import com.jbzd.media.movecartoons.databinding.ItemAppVerticalBinding;
import com.jbzd.media.movecartoons.p396ui.appstore.AppStoreActivity;
import com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.UpdateDialog;
import com.jbzd.media.movecartoons.p396ui.download.DownloadActivity;
import com.jbzd.media.movecartoons.p396ui.mine.MineFragment;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.p396ui.mine.MyVideosActivity;
import com.jbzd.media.movecartoons.p396ui.mine.child.FollowActivity;
import com.jbzd.media.movecartoons.p396ui.mine.favority.FavoriteActivity;
import com.jbzd.media.movecartoons.p396ui.mine.history.HistoryActivity;
import com.jbzd.media.movecartoons.p396ui.post.MyPostListActivity;
import com.jbzd.media.movecartoons.p396ui.search.MyBoughtActivity;
import com.jbzd.media.movecartoons.p396ui.settings.AccountCardIdActivity;
import com.jbzd.media.movecartoons.p396ui.settings.AvatarActivity;
import com.jbzd.media.movecartoons.p396ui.settings.SettingActivity;
import com.jbzd.media.movecartoons.p396ui.settings.UserInfoSexActivity;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.p396ui.share.ShareBindActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.p396ui.web.WebActivity;
import com.jbzd.media.movecartoons.p396ui.welfare.SignInAndWelfareTasksPage;
import com.jbzd.media.movecartoons.view.PostAiTypeDialog;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMFragment;
import java.io.File;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import me.jessyan.progressmanager.body.ProgressInfo;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p013o.C0908b;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2858b;
import p005b.p327w.p330b.p337d.C2859c;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B\u0007¢\u0006\u0004\b1\u0010\u0013J\u001f\u0010\t\u001a\u00020\b2\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u000b\u001a\u00020\b2\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u0017\u0010\u000f\u001a\u00020\b2\u0006\u0010\u000e\u001a\u00020\rH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u0017\u0010\u0011\u001a\u00020\b2\u0006\u0010\u000e\u001a\u00020\rH\u0002¢\u0006\u0004\b\u0011\u0010\u0010J\u000f\u0010\u0012\u001a\u00020\bH\u0002¢\u0006\u0004\b\u0012\u0010\u0013J\u0017\u0010\u0016\u001a\u00020\b2\u0006\u0010\u0015\u001a\u00020\u0014H\u0002¢\u0006\u0004\b\u0016\u0010\u0017J\u0015\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00190\u0018H\u0002¢\u0006\u0004\b\u001a\u0010\u001bJ\u0015\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00190\u0018H\u0002¢\u0006\u0004\b\u001c\u0010\u001bJ\u0015\u0010\u001d\u001a\b\u0012\u0004\u0012\u00020\u00190\u0018H\u0002¢\u0006\u0004\b\u001d\u0010\u001bJ\u000f\u0010\u001e\u001a\u00020\bH\u0002¢\u0006\u0004\b\u001e\u0010\u0013J!\u0010#\u001a\u00020\b2\u0006\u0010 \u001a\u00020\u001f2\b\u0010\"\u001a\u0004\u0018\u00010!H\u0016¢\u0006\u0004\b#\u0010$J)\u0010*\u001a\u00020\b2\u0006\u0010&\u001a\u00020%2\u0006\u0010'\u001a\u00020%2\b\u0010)\u001a\u0004\u0018\u00010(H\u0016¢\u0006\u0004\b*\u0010+J\u000f\u0010,\u001a\u00020\bH\u0016¢\u0006\u0004\b,\u0010\u0013J\u000f\u0010-\u001a\u00020\bH\u0016¢\u0006\u0004\b-\u0010\u0013R\u0018\u0010/\u001a\u0004\u0018\u00010.8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b/\u00100¨\u00062"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MineFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMFragment;", "Lcom/jbzd/media/movecartoons/databinding/FragMineBinding;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;", "systemInfoBean", "", "isMandatoryUpdate", "", "showUpdateDialog", "(Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;Z)V", "downloadNewVersion", "(Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;)V", "", "filePath", "requestInstall", "(Ljava/lang/String;)V", "grantedInstallApk", "refreshUserInfo", "()V", "Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;", "userInfoBean", "setUserInfo", "(Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;)V", "", "Lb/a/a/a/o/b;", "generateItemsOne", "()Ljava/util/List;", "generateItemsThree", "generateGrid", "showPostAiTypeDialog", "Landroid/view/View;", "view", "Landroid/os/Bundle;", "savedInstanceState", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "", "requestCode", "resultCode", "Landroid/content/Intent;", "data", "onActivityResult", "(IILandroid/content/Intent;)V", "initViews", "onResume", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "mPostAiTypeDialog", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineFragment extends BaseVMFragment<FragMineBinding, MineViewModel> {

    @Nullable
    private PostAiTypeDialog mPostAiTypeDialog;

    /* JADX WARN: Multi-variable type inference failed */
    public static final /* synthetic */ FragMineBinding access$getBodyBinding(MineFragment mineFragment) {
        return (FragMineBinding) mineFragment.getBodyBinding();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void downloadNewVersion(SystemInfoBean systemInfoBean) {
        String str = systemInfoBean.download_url;
        final ProgressDialog progressDialog = new ProgressDialog(requireContext());
        progressDialog.setProgressStyle(1);
        progressDialog.setTitle("下载中...");
        progressDialog.setCancelable(false);
        progressDialog.setCanceledOnTouchOutside(false);
        progressDialog.setMax(100);
        progressDialog.show();
        if (C2859c.f7782a == null) {
            C2859c.f7782a = new C2859c();
        }
        C2859c c2859c = C2859c.f7782a;
        MyApp myApp = MyApp.f9891f;
        File externalFilesDir = MyApp.m4183d().getExternalFilesDir("apk");
        Intrinsics.checkNotNull(externalFilesDir);
        String absolutePath = externalFilesDir.getAbsolutePath();
        Intrinsics.checkNotNullExpressionValue(absolutePath, "MyApp.instance.getExternalFilesDir(\"apk\")!!.absolutePath");
        c2859c.m3302a(str, absolutePath, "new.apk", new C2859c.c() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$downloadNewVersion$1
            @Override // p005b.p327w.p330b.p337d.C2859c.c
            public void onDownloadFailed() {
                Looper.prepare();
                C2354n.m2379B1("下载失败，请重试");
                Looper.loop();
            }

            @Override // p005b.p327w.p330b.p337d.C2859c.c
            public void onDownloadSuccess() {
                progressDialog.dismiss();
                MineFragment mineFragment = this;
                StringBuilder sb = new StringBuilder();
                MyApp myApp2 = MyApp.f9891f;
                File externalFilesDir2 = MyApp.m4183d().getExternalFilesDir("apk");
                Intrinsics.checkNotNull(externalFilesDir2);
                String absolutePath2 = externalFilesDir2.getAbsolutePath();
                Intrinsics.checkNotNullExpressionValue(absolutePath2, "MyApp.instance.getExternalFilesDir(\"apk\")!!.absolutePath");
                sb.append(absolutePath2);
                sb.append((Object) File.separator);
                sb.append("new.apk");
                mineFragment.requestInstall(sb.toString());
            }

            @Override // p005b.p327w.p330b.p337d.C2859c.c
            public void onDownloadSuccessData(@NotNull String data) {
                Intrinsics.checkNotNullParameter(data, "data");
                progressDialog.dismiss();
            }

            @Override // p005b.p327w.p330b.p337d.C2859c.c
            public void onDownloading(@Nullable ProgressInfo progress) {
                if (progress == null) {
                    return;
                }
                progressDialog.setProgress(progress.m5618b());
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<C0908b> generateGrid() {
        return CollectionsKt__CollectionsKt.listOf((Object[]) new C0908b[]{new C0908b(R.drawable.mine_footprints, "浏览记录", "", 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateGrid$1
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                HistoryActivity.Companion companion = HistoryActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 8), new C0908b(R.drawable.mine_favorite_icon, "我的收藏", "", R.color.transparent, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateGrid$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                MineFragment.this.startActivity(new Intent(MineFragment.this.requireContext(), (Class<?>) FavoriteActivity.class));
            }
        }), new C0908b(R.drawable.mine_buy_icon, "我的购买", "", R.color.transparent, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateGrid$3
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                MyBoughtActivity.Companion companion = MyBoughtActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                MyBoughtActivity.Companion.start$default(companion, requireContext, 0, 2, null);
            }
        }), new C0908b(R.drawable.icon_me_share, "邀请好友", "", R.color.transparent, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateGrid$4
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                InviteActivity.Companion companion = InviteActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        })});
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<C0908b> generateItemsOne() {
        MyApp myApp = MyApp.f9891f;
        String str = MyApp.f9892g.balance;
        Intrinsics.checkNotNullExpressionValue(str, "MyApp.userInfo.balance");
        return CollectionsKt__CollectionsKt.listOf((Object[]) new C0908b[]{new C0908b(R.drawable.mine_coin_balance, "我的帖子", str, 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsOne$1
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                MyPostListActivity.Companion companion = MyPostListActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, 0);
            }
        }, 8), new C0908b(R.drawable.mine_video, "我的视频", "", R.color.transparent, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsOne$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                MyVideosActivity.Companion companion = MyVideosActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }), new C0908b(R.drawable.mine_fans, "关注/粉丝", null, 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsOne$3
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                FollowActivity.Companion companion = FollowActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, "0");
            }
        }, 12), new C0908b(R.drawable.iv_mine_cache, "我的缓存", "", 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsOne$4
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                DownloadActivity.Companion companion = DownloadActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 8)});
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<C0908b> generateItemsThree() {
        String str;
        C0908b[] c0908bArr = new C0908b[8];
        c0908bArr[0] = new C0908b(R.drawable.mine_ai_icon, "AI定制", null, 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsThree$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                C4909c.m5569b().m5574g(new EventChangeTab("", 2));
            }
        }, 12);
        c0908bArr[1] = new C0908b(R.drawable.mine_credentials_icon, "账号凭证", null, 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsThree$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                MineFragment.this.startActivity(new Intent(MineFragment.this.requireContext(), (Class<?>) AccountCardIdActivity.class));
            }
        }, 12);
        c0908bArr[2] = new C0908b(R.drawable.mine_binding_code, "绑定邀请", "", 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsThree$3
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                ShareBindActivity.Companion companion = ShareBindActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 8);
        c0908bArr[3] = new C0908b(R.drawable.app_recommend, "应用中心", "", 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsThree$4
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                AppStoreActivity.Companion companion = AppStoreActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 8);
        c0908bArr[4] = new C0908b(R.drawable.mine_online_service, "在线客服", "", 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsThree$5
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                Boolean valueOf;
                Context context = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext()");
                Intrinsics.checkNotNullParameter(context, "context");
                MyApp myApp = MyApp.f9891f;
                String str2 = MyApp.f9897l;
                if (str2 == null) {
                    valueOf = null;
                } else {
                    valueOf = Boolean.valueOf(str2.length() > 0);
                }
                if (!Intrinsics.areEqual(valueOf, Boolean.TRUE)) {
                    ChatDetailActivity.Companion.start$default(ChatDetailActivity.INSTANCE, context, null, null, null, null, 30, null);
                    return;
                }
                String str3 = MyApp.f9897l;
                if (str3 == null) {
                    return;
                }
                WebActivity.INSTANCE.start(context, str3);
            }
        }, 8);
        c0908bArr[5] = new C0908b(R.drawable.mine_service_group, "官方商务", "", 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsThree$6
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                C0840d.a aVar = C0840d.f235a;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                MyApp myApp = MyApp.f9891f;
                String str2 = MyApp.m4185f().group_link;
                if (str2 == null) {
                    str2 = "";
                }
                C0840d.a.m174d(aVar, requireContext, str2, null, null, 12);
            }
        }, 8);
        PackageManager packageManager = C4195m.m4792Y().getPackageManager();
        Intrinsics.checkNotNullExpressionValue(packageManager, "getApp().packageManager");
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(C4195m.m4792Y().getPackageName(), 0);
            Intrinsics.checkNotNullExpressionValue(packageInfo, "pm.getPackageInfo(Utils.getApp().packageName, 0)");
            str = packageInfo.versionName;
            Intrinsics.checkNotNullExpressionValue(str, "packageInfo.versionName");
        } catch (PackageManager.NameNotFoundException e2) {
            e2.printStackTrace();
            str = "";
        }
        c0908bArr[6] = new C0908b(R.drawable.app_version_upgrade, "检测更新", Intrinsics.stringPlus("Ver", str), 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsThree$7
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                MineViewModel viewModel;
                viewModel = MineFragment.this.getViewModel();
                viewModel.loadAppInfo();
            }
        }, 8);
        c0908bArr[7] = new C0908b(R.drawable.mine_setting, "设置", "", 0, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$generateItemsThree$8
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                SettingActivity.Companion companion = SettingActivity.INSTANCE;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 8);
        return CollectionsKt__CollectionsKt.listOf((Object[]) c0908bArr);
    }

    private final void grantedInstallApk(String filePath) {
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        C2858b.m3301b(requireContext, new File(filePath));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5860initViews$lambda2$lambda1(MineFragment this$0, SystemInfoBean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (it.isMustUpdate()) {
            Intrinsics.checkNotNullExpressionValue(it, "it");
            this$0.showUpdateDialog(it, true);
        } else if (!it.isCanUpdate()) {
            C2354n.m2409L1("当前已是最新版本");
        } else {
            Intrinsics.checkNotNullExpressionValue(it, "it");
            this$0.showUpdateDialog(it, false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void refreshUserInfo() {
        C2354n.m2438V0(getViewModel().userInfoV2(), this, false, new Function1<Throwable, Boolean>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$refreshUserInfo$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Boolean invoke(Throwable th) {
                return Boolean.valueOf(invoke2(th));
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final boolean invoke2(@NotNull Throwable it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PageRefreshLayout pageRefreshLayout = MineFragment.access$getBodyBinding(MineFragment.this).mineRefresh;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.mineRefresh");
                PageRefreshLayout.m3948B(pageRefreshLayout, false, false, 3, null);
                return false;
            }
        }, new Function1<UserInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$refreshUserInfo$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(UserInfoBean userInfoBean) {
                invoke2(userInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull UserInfoBean lifecycle) {
                Intrinsics.checkNotNullParameter(lifecycle, "$this$lifecycle");
                PageRefreshLayout pageRefreshLayout = MineFragment.access$getBodyBinding(MineFragment.this).mineRefresh;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.mineRefresh");
                PageRefreshLayout.m3948B(pageRefreshLayout, false, false, 3, null);
                MyApp myApp = MyApp.f9891f;
                if (MyApp.f9892g == null) {
                    MyApp.m4189j(new UserInfoBean());
                }
                MyApp.m4189j(lifecycle);
                MineFragment.this.setUserInfo(lifecycle);
            }
        }, 2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void requestInstall(String filePath) {
        if (Build.VERSION.SDK_INT < 26) {
            grantedInstallApk(filePath);
        } else if (requireContext().getPackageManager().canRequestPackageInstalls()) {
            grantedInstallApk(filePath);
        } else {
            C2354n.m2379B1(getString(R.string.toast_no_permission));
            startActivityForResult(new Intent("android.settings.MANAGE_UNKNOWN_APP_SOURCES", Uri.parse(Intrinsics.stringPlus("package:", requireContext().getPackageName()))), 10010);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setUserInfo(final UserInfoBean userInfoBean) {
        bodyBinding(new Function1<FragMineBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$setUserInfo$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FragMineBinding fragMineBinding) {
                invoke2(fragMineBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull FragMineBinding bodyBinding) {
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                bodyBinding.tvNameNew.setText(UserInfoBean.this.nickname);
                bodyBinding.tvNumNew.setText(this.getString(R.string.mine_num, UserInfoBean.this.username));
                C2354n.m2455a2(this.requireContext()).m3298p(UserInfoBean.this.img).m3292f0().m757R(bodyBinding.ivUserAvater);
                RecyclerView rvAds = bodyBinding.rvAds;
                Intrinsics.checkNotNullExpressionValue(rvAds, "rvAds");
                List<AdBean> list = UserInfoBean.this.ico_ads;
                Intrinsics.checkNotNullParameter(rvAds, "<this>");
                C4195m.m4793Z(rvAds).m3939q(list);
                C2354n.m2455a2(this.requireContext()).m3297o(Integer.valueOf(UserInfoBean.this.sex.equals("1") ? R.drawable.icon_sexmale : R.drawable.icon_sexfemale)).m757R(bodyBinding.ivUserSex);
                C2354n.m2455a2(this.requireContext()).m3297o(Integer.valueOf(UserInfoBean.this.isVipUser() ? R.drawable.icon_viptips_goon : R.drawable.icon_viptips_show)).m757R(bodyBinding.ivViptipsShow);
                bodyBinding.tvBalance.setText(Intrinsics.stringPlus("余额 ", UserInfoBean.this.balance));
                if (UserInfoBean.this.isVipUser()) {
                    bodyBinding.tvGroupName.setVisibility(0);
                    bodyBinding.tvGroupEndtime.setVisibility(0);
                    bodyBinding.tvGroupName.setText(UserInfoBean.this.group_name);
                    bodyBinding.tvGroupEndtime.setText(UserInfoBean.this.group_end_time);
                    bodyBinding.tvGroupTitle.setText(UserInfoBean.this.group_name);
                    bodyBinding.beVip.setText(Intrinsics.stringPlus(UserInfoBean.this.group_end_time, " 到期"));
                } else {
                    bodyBinding.tvGroupName.setVisibility(0);
                    bodyBinding.tvGroupEndtime.setVisibility(8);
                    bodyBinding.tvGroupName.setText("升级为VIP获取更多权益");
                }
                Group vipGroupIds = bodyBinding.vipGroupIds;
                Intrinsics.checkNotNullExpressionValue(vipGroupIds, "vipGroupIds");
                vipGroupIds.setVisibility(UserInfoBean.this.isVipUser() ? 0 : 8);
            }
        });
    }

    private final void showPostAiTypeDialog() {
        PostAiTypeDialog postAiTypeDialog;
        if (this.mPostAiTypeDialog == null) {
            PostAiTypeDialog.Companion companion = PostAiTypeDialog.INSTANCE;
            FragmentActivity requireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
            this.mPostAiTypeDialog = companion.showPostTypeDialog(requireActivity, this);
        }
        PostAiTypeDialog postAiTypeDialog2 = this.mPostAiTypeDialog;
        Intrinsics.checkNotNull(postAiTypeDialog2);
        postAiTypeDialog2.setFragment(this);
        PostAiTypeDialog postAiTypeDialog3 = this.mPostAiTypeDialog;
        if (postAiTypeDialog3 != null) {
            if (!Intrinsics.areEqual(postAiTypeDialog3 == null ? null : Boolean.valueOf(postAiTypeDialog3.isShowing()), Boolean.FALSE) || (postAiTypeDialog = this.mPostAiTypeDialog) == null) {
                return;
            }
            postAiTypeDialog.show();
        }
    }

    private final void showUpdateDialog(final SystemInfoBean systemInfoBean, boolean isMandatoryUpdate) {
        String version = systemInfoBean.version;
        String str = systemInfoBean.version_description;
        if (str == null) {
            str = "";
        }
        String str2 = str;
        Intrinsics.checkNotNullExpressionValue(version, "version");
        Intrinsics.checkNotNullExpressionValue(str2, "if (systemInfoBean.version_description == null) \"\" else systemInfoBean.version_description");
        new UpdateDialog(version, isMandatoryUpdate, str2, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$showUpdateDialog$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                C0840d.a aVar = C0840d.f235a;
                Context requireContext = MineFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                C0840d.a.m174d(aVar, requireContext, systemInfoBean.site_url, null, null, 12);
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$showUpdateDialog$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                MineFragment.this.downloadNewVersion(systemInfoBean);
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$showUpdateDialog$3
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        }).show(getChildFragmentManager(), "updateDialog");
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMFragment, com.qunidayede.supportlibrary.core.view.BaseBindingFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        getViewModel().getSysTem().observe(this, new Observer() { // from class: b.a.a.a.t.h.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MineFragment.m5860initViews$lambda2$lambda1(MineFragment.this, (SystemInfoBean) obj);
            }
        });
        MyApp myApp = MyApp.f9891f;
        setUserInfo(MyApp.f9892g);
        ((FragMineBinding) getBodyBinding()).mineRefresh.m3954D(new Function1<PageRefreshLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$initViews$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PageRefreshLayout pageRefreshLayout) {
                invoke2(pageRefreshLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull PageRefreshLayout onRefresh) {
                Intrinsics.checkNotNullParameter(onRefresh, "$this$onRefresh");
                MineFragment.this.refreshUserInfo();
            }
        });
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 10010) {
            StringBuilder sb = new StringBuilder();
            MyApp myApp = MyApp.f9891f;
            File externalFilesDir = MyApp.m4183d().getExternalFilesDir("apk");
            Intrinsics.checkNotNull(externalFilesDir);
            String absolutePath = externalFilesDir.getAbsolutePath();
            Intrinsics.checkNotNullExpressionValue(absolutePath, "MyApp.instance.getExternalFilesDir(\"apk\")!!.absolutePath");
            sb.append(absolutePath);
            sb.append((Object) File.separator);
            sb.append("new.apk");
            grantedInstallApk(sb.toString());
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        refreshUserInfo();
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.qunidayede.supportlibrary.core.view.BaseVMFragment, androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        String str;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
        TextView textView = ((FragMineBinding) getBodyBinding()).tvVersionName;
        PackageManager packageManager = C4195m.m4792Y().getPackageManager();
        Intrinsics.checkNotNullExpressionValue(packageManager, "getApp().packageManager");
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(C4195m.m4792Y().getPackageName(), 0);
            Intrinsics.checkNotNullExpressionValue(packageInfo, "pm.getPackageInfo(Utils.getApp().packageName, 0)");
            str = packageInfo.versionName;
            Intrinsics.checkNotNullExpressionValue(str, "packageInfo.versionName");
        } catch (PackageManager.NameNotFoundException e2) {
            e2.printStackTrace();
            str = "";
        }
        textView.setText(Intrinsics.stringPlus("V ", str));
        bodyBinding(new Function1<FragMineBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FragMineBinding fragMineBinding) {
                invoke2(fragMineBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull FragMineBinding bodyBinding) {
                List<? extends Object> generateGrid;
                List<? extends Object> generateItemsOne;
                List<? extends Object> generateItemsThree;
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                RecyclerView rvAds = bodyBinding.rvAds;
                Intrinsics.checkNotNullExpressionValue(rvAds, "rvAds");
                C4195m.m4821n0(rvAds, 5, 0, false, false, 14);
                int m4785R = C4195m.m4785R(10.0f);
                DividerOrientation dividerOrientation = DividerOrientation.GRID;
                C4195m.m4784Q(rvAds, m4785R, dividerOrientation);
                final MineFragment mineFragment = MineFragment.this;
                C4195m.m4774J0(rvAds, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.1
                    {
                        super(2);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", AdBean.class);
                        final int i2 = R.layout.item_app_vertical;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(AdBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1$1$invoke$$inlined$addType$1
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        } else {
                            bindingAdapter.f8909k.put(Reflection.typeOf(AdBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1$1$invoke$$inlined$addType$2
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        }
                        final MineFragment mineFragment2 = MineFragment.this;
                        bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment.onViewCreated.1.1.1
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                                invoke2(bindingViewHolder);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                                ItemAppVerticalBinding itemAppVerticalBinding;
                                Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                                ViewBinding viewBinding = onBind.f8929e;
                                if (viewBinding == null) {
                                    Object invoke = ItemAppVerticalBinding.class.getMethod("bind", View.class).invoke(null, onBind.itemView);
                                    Objects.requireNonNull(invoke, "null cannot be cast to non-null type com.jbzd.media.movecartoons.databinding.ItemAppVerticalBinding");
                                    itemAppVerticalBinding = (ItemAppVerticalBinding) invoke;
                                    onBind.f8929e = itemAppVerticalBinding;
                                } else {
                                    Objects.requireNonNull(viewBinding, "null cannot be cast to non-null type com.jbzd.media.movecartoons.databinding.ItemAppVerticalBinding");
                                    itemAppVerticalBinding = (ItemAppVerticalBinding) viewBinding;
                                }
                                MineFragment mineFragment3 = MineFragment.this;
                                AdBean adBean = (AdBean) onBind.m3942b();
                                itemAppVerticalBinding.txtName.setText(adBean.name);
                                C2354n.m2455a2(mineFragment3.requireContext()).m3298p(adBean.content).m3295i0().m757R(itemAppVerticalBinding.imgIcon);
                            }
                        });
                        int[] iArr = {R.id.root};
                        final MineFragment mineFragment3 = MineFragment.this;
                        bindingAdapter.m3937n(iArr, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment.onViewCreated.1.1.2
                            {
                                super(2);
                            }

                            @Override // kotlin.jvm.functions.Function2
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                                invoke(bindingViewHolder, num.intValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                                MineViewModel.Companion companion = MineViewModel.INSTANCE;
                                String str2 = ((AdBean) onClick.m3942b()).f10014id;
                                Intrinsics.checkNotNullExpressionValue(str2, "getModel<AdBean>().id");
                                String str3 = ((AdBean) onClick.m3942b()).name;
                                Intrinsics.checkNotNullExpressionValue(str3, "getModel<AdBean>().name");
                                companion.systemTrack("ad", str2, str3);
                                C0840d.a aVar = C0840d.f235a;
                                Context requireContext = MineFragment.this.requireContext();
                                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                                C0840d.a.m174d(aVar, requireContext, ((AdBean) onClick.m3942b()).link, null, null, 12);
                            }
                        });
                    }
                });
                RecyclerView gridView = bodyBinding.gridView;
                Intrinsics.checkNotNullExpressionValue(gridView, "gridView");
                C4195m.m4821n0(gridView, 4, 0, false, false, 14);
                C4195m.m4784Q(gridView, C4195m.m4785R(12.0f), dividerOrientation);
                BindingAdapter m4774J0 = C4195m.m4774J0(gridView, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.2
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", C0908b.class);
                        final int i2 = R.layout.item_mine_grid;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(C0908b.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1$2$invoke$$inlined$addType$1
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        } else {
                            bindingAdapter.f8909k.put(Reflection.typeOf(C0908b.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1$2$invoke$$inlined$addType$2
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        }
                        bindingAdapter.m3937n(new int[]{R.id.root}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment.onViewCreated.1.2.1
                            @Override // kotlin.jvm.functions.Function2
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                                invoke(bindingViewHolder, num.intValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                                Function0<Unit> function0 = ((C0908b) onClick.m3942b()).f363e;
                                if (function0 == null) {
                                    return;
                                }
                                function0.invoke();
                            }
                        });
                    }
                });
                generateGrid = MineFragment.this.generateGrid();
                m4774J0.m3939q(generateGrid);
                RecyclerView rvMineOne = bodyBinding.rvMineOne;
                Intrinsics.checkNotNullExpressionValue(rvMineOne, "rvMineOne");
                C4195m.m4821n0(rvMineOne, 4, 0, false, false, 14);
                C4195m.m4784Q(rvMineOne, C4195m.m4785R(12.0f), dividerOrientation);
                BindingAdapter m4774J02 = C4195m.m4774J0(rvMineOne, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.3
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", C0908b.class);
                        final int i2 = R.layout.item_mine_grid;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(C0908b.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1$3$invoke$$inlined$addType$1
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        } else {
                            bindingAdapter.f8909k.put(Reflection.typeOf(C0908b.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1$3$invoke$$inlined$addType$2
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        }
                        bindingAdapter.m3937n(new int[]{R.id.root}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment.onViewCreated.1.3.1
                            @Override // kotlin.jvm.functions.Function2
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                                invoke(bindingViewHolder, num.intValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                                Function0<Unit> function0 = ((C0908b) onClick.m3942b()).f363e;
                                if (function0 == null) {
                                    return;
                                }
                                function0.invoke();
                            }
                        });
                        bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment.onViewCreated.1.3.2
                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                                invoke2(bindingViewHolder);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                                Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                                ((TextView) onBind.m3941a(R.id.tv_item_name)).setText(((C0908b) onBind.m3942b()).f361c);
                            }
                        });
                    }
                });
                generateItemsOne = MineFragment.this.generateItemsOne();
                m4774J02.m3939q(generateItemsOne);
                RecyclerView rvMineThree = bodyBinding.rvMineThree;
                Intrinsics.checkNotNullExpressionValue(rvMineThree, "rvMineThree");
                C4195m.m4821n0(rvMineThree, 4, 0, false, false, 14);
                C4195m.m4784Q(rvMineThree, C4195m.m4785R(12.0f), dividerOrientation);
                BindingAdapter m4774J03 = C4195m.m4774J0(rvMineThree, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.4
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", C0908b.class);
                        final int i2 = R.layout.item_mine_grid;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(C0908b.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1$4$invoke$$inlined$addType$1
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        } else {
                            bindingAdapter.f8909k.put(Reflection.typeOf(C0908b.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1$4$invoke$$inlined$addType$2
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        }
                        bindingAdapter.m3937n(new int[]{R.id.root}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment.onViewCreated.1.4.1
                            @Override // kotlin.jvm.functions.Function2
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                                invoke(bindingViewHolder, num.intValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                                Function0<Unit> function0 = ((C0908b) onClick.m3942b()).f363e;
                                if (function0 == null) {
                                    return;
                                }
                                function0.invoke();
                            }
                        });
                        bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment.onViewCreated.1.4.2
                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                                invoke2(bindingViewHolder);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                                Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                                ((TextView) onBind.m3941a(R.id.tv_item_name)).setText(((C0908b) onBind.m3942b()).f361c);
                            }
                        });
                    }
                });
                generateItemsThree = MineFragment.this.generateItemsThree();
                m4774J03.m3939q(generateItemsThree);
                MineFragment mineFragment2 = MineFragment.this;
                ShapeableImageView ivUserAvater = bodyBinding.ivUserAvater;
                Intrinsics.checkNotNullExpressionValue(ivUserAvater, "ivUserAvater");
                BaseVMFragment.fadeWhenTouch$default(mineFragment2, ivUserAvater, 0.0f, 1, null);
                ShapeableImageView shapeableImageView = bodyBinding.ivUserAvater;
                final MineFragment mineFragment3 = MineFragment.this;
                C2354n.m2374A(shapeableImageView, 0L, new Function1<ShapeableImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.5
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(ShapeableImageView shapeableImageView2) {
                        invoke2(shapeableImageView2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull ShapeableImageView it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        AvatarActivity.Companion companion = AvatarActivity.INSTANCE;
                        Context requireContext = MineFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        companion.start(requireContext);
                    }
                }, 1);
                MineFragment mineFragment4 = MineFragment.this;
                ImageView ivUserSex = bodyBinding.ivUserSex;
                Intrinsics.checkNotNullExpressionValue(ivUserSex, "ivUserSex");
                BaseVMFragment.fadeWhenTouch$default(mineFragment4, ivUserSex, 0.0f, 1, null);
                ImageView imageView = bodyBinding.ivUserSex;
                final MineFragment mineFragment5 = MineFragment.this;
                C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.6
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView2) {
                        invoke2(imageView2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull ImageView it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        UserInfoSexActivity.Companion companion = UserInfoSexActivity.INSTANCE;
                        Context requireContext = MineFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        companion.start(requireContext);
                    }
                }, 1);
                MineFragment mineFragment6 = MineFragment.this;
                LinearLayout llServiceOnline = bodyBinding.llServiceOnline;
                Intrinsics.checkNotNullExpressionValue(llServiceOnline, "llServiceOnline");
                BaseVMFragment.fadeWhenTouch$default(mineFragment6, llServiceOnline, 0.0f, 1, null);
                LinearLayout linearLayout = bodyBinding.llServiceOnline;
                final MineFragment mineFragment7 = MineFragment.this;
                C2354n.m2374A(linearLayout, 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.7
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout2) {
                        invoke2(linearLayout2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayout it) {
                        Boolean valueOf;
                        Intrinsics.checkNotNullParameter(it, "it");
                        Context context = MineFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(context, "requireContext()");
                        Intrinsics.checkNotNullParameter(context, "context");
                        MyApp myApp = MyApp.f9891f;
                        String str2 = MyApp.f9897l;
                        if (str2 == null) {
                            valueOf = null;
                        } else {
                            valueOf = Boolean.valueOf(str2.length() > 0);
                        }
                        if (!Intrinsics.areEqual(valueOf, Boolean.TRUE)) {
                            ChatDetailActivity.Companion.start$default(ChatDetailActivity.INSTANCE, context, null, null, null, null, 30, null);
                            return;
                        }
                        String str3 = MyApp.f9897l;
                        if (str3 == null) {
                            return;
                        }
                        WebActivity.INSTANCE.start(context, str3);
                    }
                }, 1);
                MineFragment mineFragment8 = MineFragment.this;
                LinearLayout llServiceGroup = bodyBinding.llServiceGroup;
                Intrinsics.checkNotNullExpressionValue(llServiceGroup, "llServiceGroup");
                BaseVMFragment.fadeWhenTouch$default(mineFragment8, llServiceGroup, 0.0f, 1, null);
                LinearLayout linearLayout2 = bodyBinding.llServiceGroup;
                final MineFragment mineFragment9 = MineFragment.this;
                C2354n.m2374A(linearLayout2, 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.8
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout3) {
                        invoke2(linearLayout3);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayout it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        C0840d.a aVar = C0840d.f235a;
                        Context requireContext = MineFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        MyApp myApp = MyApp.f9891f;
                        String str2 = MyApp.m4185f().group_link;
                        if (str2 == null) {
                            str2 = "";
                        }
                        C0840d.a.m174d(aVar, requireContext, str2, null, null, 12);
                    }
                }, 1);
                MineFragment mineFragment10 = MineFragment.this;
                LinearLayout llServiceApplist = bodyBinding.llServiceApplist;
                Intrinsics.checkNotNullExpressionValue(llServiceApplist, "llServiceApplist");
                BaseVMFragment.fadeWhenTouch$default(mineFragment10, llServiceApplist, 0.0f, 1, null);
                LinearLayout linearLayout3 = bodyBinding.llServiceApplist;
                final MineFragment mineFragment11 = MineFragment.this;
                C2354n.m2374A(linearLayout3, 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.9
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout4) {
                        invoke2(linearLayout4);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayout it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        AppStoreActivity.Companion companion = AppStoreActivity.INSTANCE;
                        Context requireContext = MineFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        companion.start(requireContext);
                    }
                }, 1);
                MineFragment mineFragment12 = MineFragment.this;
                TextView ivSetting = bodyBinding.ivSetting;
                Intrinsics.checkNotNullExpressionValue(ivSetting, "ivSetting");
                BaseVMFragment.fadeWhenTouch$default(mineFragment12, ivSetting, 0.0f, 1, null);
                C2354n.m2374A(bodyBinding.ivSetting, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.10
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                        invoke2(textView2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull TextView it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        SettingActivity.Companion companion = SettingActivity.INSTANCE;
                        Context context = it.getContext();
                        Intrinsics.checkNotNullExpressionValue(context, "it.context");
                        companion.start(context);
                    }
                }, 1);
                MineFragment mineFragment13 = MineFragment.this;
                ImageView ivSharePromotion = bodyBinding.ivSharePromotion;
                Intrinsics.checkNotNullExpressionValue(ivSharePromotion, "ivSharePromotion");
                BaseVMFragment.fadeWhenTouch$default(mineFragment13, ivSharePromotion, 0.0f, 1, null);
                MineFragment mineFragment14 = MineFragment.this;
                RelativeLayout llVipInfos = bodyBinding.llVipInfos;
                Intrinsics.checkNotNullExpressionValue(llVipInfos, "llVipInfos");
                BaseVMFragment.fadeWhenTouch$default(mineFragment14, llVipInfos, 0.0f, 1, null);
                MineFragment mineFragment15 = MineFragment.this;
                RelativeLayout rlGoVip = bodyBinding.rlGoVip;
                Intrinsics.checkNotNullExpressionValue(rlGoVip, "rlGoVip");
                BaseVMFragment.fadeWhenTouch$default(mineFragment15, rlGoVip, 0.0f, 1, null);
                MineFragment mineFragment16 = MineFragment.this;
                RelativeLayout rlGoRecharge = bodyBinding.rlGoRecharge;
                Intrinsics.checkNotNullExpressionValue(rlGoRecharge, "rlGoRecharge");
                BaseVMFragment.fadeWhenTouch$default(mineFragment16, rlGoRecharge, 0.0f, 1, null);
                MineFragment mineFragment17 = MineFragment.this;
                ImageTextView itvSignMine = bodyBinding.itvSignMine;
                Intrinsics.checkNotNullExpressionValue(itvSignMine, "itvSignMine");
                BaseVMFragment.fadeWhenTouch$default(mineFragment17, itvSignMine, 0.0f, 1, null);
                C2354n.m2374A(bodyBinding.ivSharePromotion, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.11
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView2) {
                        invoke2(imageView2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull ImageView it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        InviteActivity.Companion companion = InviteActivity.INSTANCE;
                        Context context = it.getContext();
                        Intrinsics.checkNotNullExpressionValue(context, "it.context");
                        companion.start(context);
                    }
                }, 1);
                C2354n.m2374A(bodyBinding.llVipInfos, 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.12
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                        invoke2(relativeLayout);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull RelativeLayout it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        BuyActivity.Companion companion = BuyActivity.INSTANCE;
                        Context context = it.getContext();
                        Intrinsics.checkNotNullExpressionValue(context, "it.context");
                        companion.start(context);
                    }
                }, 1);
                C2354n.m2374A(bodyBinding.rlGoVip, 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.13
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                        invoke2(relativeLayout);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull RelativeLayout it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        BuyActivity.Companion companion = BuyActivity.INSTANCE;
                        Context context = it.getContext();
                        Intrinsics.checkNotNullExpressionValue(context, "it.context");
                        companion.start(context);
                    }
                }, 1);
                C2354n.m2374A(bodyBinding.rlGoRecharge, 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.14
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                        invoke2(relativeLayout);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull RelativeLayout it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        RechargeActivity.Companion companion = RechargeActivity.INSTANCE;
                        Context context = it.getContext();
                        Intrinsics.checkNotNullExpressionValue(context, "it.context");
                        companion.start(context);
                    }
                }, 1);
                ImageTextView imageTextView = bodyBinding.itvSignMine;
                final MineFragment mineFragment18 = MineFragment.this;
                C2354n.m2374A(imageTextView, 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineFragment$onViewCreated$1.15
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView2) {
                        invoke2(imageTextView2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull ImageTextView it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        SignInAndWelfareTasksPage.Companion companion = SignInAndWelfareTasksPage.INSTANCE;
                        Context requireContext = MineFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        companion.start(requireContext);
                    }
                }, 1);
            }
        });
    }
}

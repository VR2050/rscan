package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.appcompat.widget.AppCompatButton;
import androidx.lifecycle.LifecycleCoroutineScope;
import androidx.lifecycle.LifecycleOwnerKt;
import androidx.lifecycle.Observer;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.annotaion.DividerOrientation;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.UploadPicResponse;
import com.jbzd.media.movecartoons.bean.response.HeadImageBean;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.jbzd.media.movecartoons.databinding.ActAvatarBinding;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.luck.picture.lib.PictureSelector;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import java.util.ArrayList;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0875w;
import p005b.p006a.p007a.p008a.p017r.p022o.C0949c;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.p381a.C2964m;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u0000 \u001f2\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0001\u001fB\u0007¢\u0006\u0004\b\u001e\u0010\u0006J\u000f\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\t\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u000b\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\u000b\u0010\nJ\u000f\u0010\f\u001a\u00020\u0004H\u0014¢\u0006\u0004\b\f\u0010\u0006J\u000f\u0010\r\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u000f\u0010\u0006J\u000f\u0010\u0010\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0010\u0010\u0006R$\u0010\u0012\u001a\u0004\u0018\u00010\u00118\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\u0017R\u001d\u0010\u001d\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001c¨\u0006 "}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/AvatarActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActAvatarBinding;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "", "chooseNativeImg", "()V", "", "filePath", "parsePhoto", "(Ljava/lang/String;)V", "doUploadFile", "onStop", "getTopBarTitle", "()Ljava/lang/String;", "initView", "bindEvent", "Lc/a/d1;", "jobUpload", "Lc/a/d1;", "getJobUpload", "()Lc/a/d1;", "setJobUpload", "(Lc/a/d1;)V", "Lcom/google/android/material/imageview/ShapeableImageView;", "civ_head$delegate", "Lkotlin/Lazy;", "getCiv_head", "()Lcom/google/android/material/imageview/ShapeableImageView;", "civ_head", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AvatarActivity extends BaseVMActivity<ActAvatarBinding, MineViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: civ_head$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy civ_head = LazyKt__LazyJVMKt.lazy(new Function0<ShapeableImageView>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$civ_head$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ShapeableImageView invoke() {
            ShapeableImageView shapeableImageView = (ShapeableImageView) AvatarActivity.this.findViewById(R.id.civ_head);
            Intrinsics.checkNotNull(shapeableImageView);
            return shapeableImageView;
        }
    });

    @Nullable
    private InterfaceC3053d1 jobUpload;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/AvatarActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, AvatarActivity.class);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final /* synthetic */ ActAvatarBinding access$getBodyBinding(AvatarActivity avatarActivity) {
        return (ActAvatarBinding) avatarActivity.getBodyBinding();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void chooseNativeImg() {
        PictureSelector.create(this).openGallery(PictureMimeType.ofImage()).imageEngine(C0875w.m204a()).selectionMode(1).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$chooseNativeImg$1
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                if (result == null || result.isEmpty()) {
                    return;
                }
                AvatarActivity avatarActivity = AvatarActivity.this;
                int i2 = Build.VERSION.SDK_INT;
                C2818e.m3272a(Intrinsics.stringPlus("Build.VERSION.SDK_INT:", Integer.valueOf(i2)), new Object[0]);
                boolean z = i2 <= 28;
                LocalMedia localMedia = result.get(0);
                String path = z ? localMedia.getPath() : localMedia.getRealPath();
                Intrinsics.checkNotNullExpressionValue(path, "if (DeviceUtil.lessAndroidQ()) result[0].path else result[0].realPath");
                avatarActivity.parsePhoto(path);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void doUploadFile(String filePath) {
        loadingDialog();
        MyApp myApp = MyApp.f9891f;
        SystemInfoBean m4185f = MyApp.m4185f();
        Intrinsics.checkNotNull(m4185f);
        String str = m4185f.upload_image_url;
        Intrinsics.checkNotNullExpressionValue(str, "MyApp.systemBean!!.upload_image_url");
        SystemInfoBean m4185f2 = MyApp.m4185f();
        Intrinsics.checkNotNull(m4185f2);
        String str2 = m4185f2.upload_image_url;
        Intrinsics.checkNotNullExpressionValue(str2, "MyApp.systemBean!!.upload_image_url");
        String substring = str.substring(0, StringsKt__StringsKt.lastIndexOf$default((CharSequence) str2, "/", 0, false, 6, (Object) null) + 1);
        Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
        SystemInfoBean m4185f3 = MyApp.m4185f();
        Intrinsics.checkNotNull(m4185f3);
        String str3 = m4185f3.upload_image_url;
        Intrinsics.checkNotNullExpressionValue(str3, "MyApp.systemBean!!.upload_image_url");
        SystemInfoBean m4185f4 = MyApp.m4185f();
        Intrinsics.checkNotNull(m4185f4);
        String str4 = m4185f4.upload_image_url;
        Intrinsics.checkNotNullExpressionValue(str4, "MyApp.systemBean!!.upload_image_url");
        String substring2 = str3.substring(StringsKt__StringsKt.indexOf$default((CharSequence) str4, "key=", 0, false, 6, (Object) null) + 4);
        Intrinsics.checkNotNullExpressionValue(substring2, "this as java.lang.String).substring(startIndex)");
        String user_id = MyApp.f9892g.user_id;
        Intrinsics.checkNotNullExpressionValue(user_id, "user_id");
        this.jobUpload = new C0949c(substring, substring2, user_id, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$doUploadFile$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str5) {
                invoke2(str5);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str5) {
                AvatarActivity.this.hideLoading();
                C2354n.m2379B1(str5);
            }
        }, "0", null, 32).m291b(filePath, new Function1<UploadPicResponse.DataBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$doUploadFile$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(UploadPicResponse.DataBean dataBean) {
                invoke2(dataBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull UploadPicResponse.DataBean it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C2852c m2467d2 = C2354n.m2467d2(AvatarActivity.this);
                String file = it.getFile();
                if (file == null) {
                    file = "";
                }
                C1558h mo770c = m2467d2.mo770c();
                mo770c.mo763X(file);
                ((C2851b) mo770c).m3292f0().m757R(AvatarActivity.this.getCiv_head());
                MineViewModel viewModel = AvatarActivity.this.getViewModel();
                String file2 = it.getFile();
                Intrinsics.checkNotNullExpressionValue(file2, "it.file");
                viewModel.updateUserInfo("img", file2);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void parsePhoto(String filePath) {
        LifecycleCoroutineScope lifecycleScope = LifecycleOwnerKt.getLifecycleScope(this);
        C3079m0 c3079m0 = C3079m0.f8432c;
        C2354n.m2435U0(lifecycleScope, C2964m.f8127b, 0, new AvatarActivity$parsePhoto$1(this, filePath, null), 2, null);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        String str;
        C2852c m2467d2 = C2354n.m2467d2(this);
        MyApp myApp = MyApp.f9891f;
        UserInfoBean userInfoBean = MyApp.f9892g;
        String str2 = "";
        if (userInfoBean != null && (str = userInfoBean.img) != null) {
            str2 = str;
        }
        C1558h mo770c = m2467d2.mo770c();
        mo770c.mo763X(str2);
        ((C2851b) mo770c).m3292f0().m757R(getCiv_head());
        MineViewModel viewModel = getViewModel();
        viewModel.getAvatarBean().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$bindEvent$lambda-4$$inlined$observe$1
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                List list = (List) t;
                ArrayList arrayList = new ArrayList();
                HeadImageBean.HeadImagesBean headImagesBean = new HeadImageBean.HeadImagesBean();
                headImagesBean.isUpload = true;
                Unit unit = Unit.INSTANCE;
                arrayList.add(headImagesBean);
                if (list != null && (!list.isEmpty())) {
                    arrayList.addAll(list);
                }
                RecyclerView recyclerView = AvatarActivity.access$getBodyBinding(AvatarActivity.this).rvContent;
                Intrinsics.checkNotNullExpressionValue(recyclerView, "bodyBinding.rvContent");
                C4195m.m4793Z(recyclerView).m3939q(arrayList);
            }
        });
        viewModel.getUserInfoUpdateSuccess().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$bindEvent$lambda-4$$inlined$observe$2
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                Boolean it = (Boolean) t;
                Intrinsics.checkNotNullExpressionValue(it, "it");
                if (!it.booleanValue()) {
                    C2354n.m2449Z("更换失败");
                    return;
                }
                RecyclerView recyclerView = AvatarActivity.access$getBodyBinding(AvatarActivity.this).rvContent;
                Intrinsics.checkNotNullExpressionValue(recyclerView, "bodyBinding.rvContent");
                int intValue = C4195m.m4793Z(recyclerView).f8923y.get(0).intValue();
                RecyclerView recyclerView2 = AvatarActivity.access$getBodyBinding(AvatarActivity.this).rvContent;
                Intrinsics.checkNotNullExpressionValue(recyclerView2, "bodyBinding.rvContent");
                HeadImageBean.HeadImagesBean headImagesBean = (HeadImageBean.HeadImagesBean) C4195m.m4793Z(recyclerView2).m3930g(intValue);
                MyApp myApp2 = MyApp.f9891f;
                MyApp.f9892g.img = headImagesBean.img;
                C2354n.m2409L1("更新头像成功");
                AvatarActivity.this.finish();
            }
        });
        C2354n.m2374A(((ActAvatarBinding) getBodyBinding()).btnSubmit, 0L, new Function1<AppCompatButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$bindEvent$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(AppCompatButton appCompatButton) {
                invoke2(appCompatButton);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull AppCompatButton it) {
                Intrinsics.checkNotNullParameter(it, "it");
                RecyclerView recyclerView = AvatarActivity.access$getBodyBinding(AvatarActivity.this).rvContent;
                Intrinsics.checkNotNullExpressionValue(recyclerView, "bodyBinding.rvContent");
                if (C4195m.m4793Z(recyclerView).f8923y.size() == 0) {
                    C2354n.m2449Z("请选择头像");
                    return;
                }
                RecyclerView recyclerView2 = AvatarActivity.access$getBodyBinding(AvatarActivity.this).rvContent;
                Intrinsics.checkNotNullExpressionValue(recyclerView2, "bodyBinding.rvContent");
                int intValue = C4195m.m4793Z(recyclerView2).f8923y.get(0).intValue();
                if (intValue < 0) {
                    C2354n.m2449Z("请选择头像");
                    return;
                }
                MineViewModel viewModel2 = AvatarActivity.this.getViewModel();
                RecyclerView recyclerView3 = AvatarActivity.access$getBodyBinding(AvatarActivity.this).rvContent;
                Intrinsics.checkNotNullExpressionValue(recyclerView3, "bodyBinding.rvContent");
                String str3 = ((HeadImageBean.HeadImagesBean) C4195m.m4793Z(recyclerView3).m3930g(intValue)).value;
                Intrinsics.checkNotNullExpressionValue(str3, "bodyBinding.rvContent.bindingAdapter.getModel<HeadImageBean.HeadImagesBean>(position).value");
                viewModel2.updateUserInfo("img", str3);
            }
        }, 1);
        C2354n.m2441W0(getViewModel().userImages(), this, new Function1<List<HeadImageBean.HeadImagesBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$bindEvent$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<HeadImageBean.HeadImagesBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull List<HeadImageBean.HeadImagesBean> lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                AvatarActivity.this.getViewModel().getAvatarBean().setValue(lifecycleLoadingDialog);
            }
        }, false, null, 12);
    }

    @NotNull
    public final ShapeableImageView getCiv_head() {
        return (ShapeableImageView) this.civ_head.getValue();
    }

    @Nullable
    public final InterfaceC3053d1 getJobUpload() {
        return this.jobUpload;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.avatar_setting);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.avatar_setting)");
        return string;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        bodyBinding(new Function1<ActAvatarBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActAvatarBinding actAvatarBinding) {
                invoke2(actAvatarBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActAvatarBinding bodyBinding) {
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                RecyclerView rvContent = bodyBinding.rvContent;
                Intrinsics.checkNotNullExpressionValue(rvContent, "rvContent");
                C4195m.m4821n0(rvContent, 4, 0, false, false, 14);
                C4195m.m4784Q(rvContent, C4195m.m4785R(12.0f), DividerOrientation.GRID);
                final AvatarActivity avatarActivity = AvatarActivity.this;
                C4195m.m4774J0(rvContent, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$initView$1.1
                    {
                        super(2);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull final BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", HeadImageBean.HeadImagesBean.class);
                        final int i2 = R.layout.item_set_portrait;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(HeadImageBean.HeadImagesBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$initView$1$1$invoke$$inlined$addType$1
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
                            bindingAdapter.f8909k.put(Reflection.typeOf(HeadImageBean.HeadImagesBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity$initView$1$1$invoke$$inlined$addType$2
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
                        bindingAdapter.m3940r(true);
                        bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity.initView.1.1.1
                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                                invoke2(bindingViewHolder);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                                String str;
                                Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                                HeadImageBean.HeadImagesBean headImagesBean = (HeadImageBean.HeadImagesBean) onBind.m3942b();
                                ShapeableImageView shapeableImageView = (ShapeableImageView) onBind.m3941a(R.id.iv_mine_avatar);
                                if (headImagesBean.isUpload) {
                                    shapeableImageView.setImageResource(R.drawable.ic_avatar_upload);
                                    return;
                                }
                                ApplicationC2828a context = C2827a.f7670a;
                                if (context == null) {
                                    Intrinsics.throwUninitializedPropertyAccessException("context");
                                    throw null;
                                }
                                Intrinsics.checkNotNullParameter(context, "context");
                                try {
                                    PackageManager packageManager = context.getPackageManager();
                                    ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128);
                                    Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
                                    str = (String) packageManager.getApplicationLabel(applicationInfo);
                                } catch (PackageManager.NameNotFoundException unused) {
                                    str = "";
                                }
                                int i3 = Intrinsics.areEqual(str != null ? Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(str, "九妖", false, 2, null)) : null, Boolean.TRUE) ? R.drawable.ic_place_holder_circle_51 : R.mipmap.ic_launcher;
                                C2852c m2455a2 = C2354n.m2455a2(onBind.f8926b);
                                String str2 = headImagesBean.img;
                                String str3 = str2 != null ? str2 : "";
                                C1558h mo770c = m2455a2.mo770c();
                                mo770c.mo763X(str3);
                                ((C2851b) mo770c).m3291e0(i3).m3292f0().m757R(shapeableImageView);
                                onBind.m3941a(R.id.iv_cover).setVisibility(headImagesBean.isChecked ? 0 : 8);
                            }
                        });
                        int[] iArr = {R.id.iv_mine_avatar};
                        final AvatarActivity avatarActivity2 = AvatarActivity.this;
                        bindingAdapter.m3937n(iArr, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity.initView.1.1.2
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                                HeadImageBean.HeadImagesBean headImagesBean = (HeadImageBean.HeadImagesBean) onClick.m3942b();
                                if (headImagesBean.isUpload) {
                                    AvatarActivity.this.chooseNativeImg();
                                } else {
                                    if (headImagesBean.isChecked) {
                                        return;
                                    }
                                    bindingAdapter.m3938o(onClick.getLayoutPosition(), true);
                                }
                            }
                        });
                        final AvatarActivity avatarActivity3 = AvatarActivity.this;
                        bindingAdapter.m3936m(new Function3<Integer, Boolean, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.AvatarActivity.initView.1.1.3
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(3);
                            }

                            @Override // kotlin.jvm.functions.Function3
                            public /* bridge */ /* synthetic */ Unit invoke(Integer num, Boolean bool, Boolean bool2) {
                                invoke(num.intValue(), bool.booleanValue(), bool2.booleanValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(int i3, boolean z, boolean z2) {
                                HeadImageBean.HeadImagesBean headImagesBean = (HeadImageBean.HeadImagesBean) BindingAdapter.this.m3930g(i3);
                                headImagesBean.isChecked = z;
                                if (z) {
                                    C2852c m2467d2 = C2354n.m2467d2(avatarActivity3);
                                    String str = headImagesBean.img;
                                    if (str == null) {
                                        str = "";
                                    }
                                    C1558h mo770c = m2467d2.mo770c();
                                    mo770c.mo763X(str);
                                    ((C2851b) mo770c).m3292f0().m757R(avatarActivity3.getCiv_head());
                                }
                                BindingAdapter.this.notifyItemChanged(i3);
                            }
                        });
                    }
                });
            }
        });
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onStop() {
        super.onStop();
        InterfaceC3053d1 interfaceC3053d1 = this.jobUpload;
        if (interfaceC3053d1 == null) {
            return;
        }
        C2354n.m2512s(interfaceC3053d1, null, 1, null);
    }

    public final void setJobUpload(@Nullable InterfaceC3053d1 interfaceC3053d1) {
        this.jobUpload = interfaceC3053d1;
    }
}

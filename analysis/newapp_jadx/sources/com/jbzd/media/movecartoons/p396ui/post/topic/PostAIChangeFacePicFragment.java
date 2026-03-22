package com.jbzd.media.movecartoons.p396ui.post.topic;

import android.annotation.SuppressLint;
import android.content.Context;
import android.view.View;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.alibaba.fastjson.JSON;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.UploadPicResponse;
import com.jbzd.media.movecartoons.bean.response.AIPostConfigsBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.trade.MediaSelectAdapter;
import com.jbzd.media.movecartoons.p396ui.post.AIViewModel;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostAIChangeFacePicFragment;
import com.jbzd.media.movecartoons.p396ui.search.MyBoughtActivity;
import com.luck.picture.lib.PictureSelectionModel;
import com.luck.picture.lib.PictureSelector;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0875w;
import p005b.p006a.p007a.p008a.p017r.p022o.C0949c;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0011\u0018\u0000 ^2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001^B\u0007¢\u0006\u0004\b]\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u001f\u0010\n\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\f\u0010\u0005J\u000f\u0010\r\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\r\u0010\u0005J\u000f\u0010\u000e\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u000e\u0010\u0005J\u000f\u0010\u000f\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u000f\u0010\u0005J\u000f\u0010\u0010\u001a\u00020\bH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0012\u0010\u0013J\u000f\u0010\u0014\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0014\u0010\u0005J\u0017\u0010\u0017\u001a\u00020\u00032\u0006\u0010\u0016\u001a\u00020\u0015H\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u000f\u0010\u0019\u001a\u00020\u0003H\u0017¢\u0006\u0004\b\u0019\u0010\u0005J\u000f\u0010\u001a\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u001a\u0010\u0005R\u001d\u0010 \u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u001d\u001a\u0004\b\u001e\u0010\u001fR\u001d\u0010%\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u001d\u001a\u0004\b#\u0010$R\u001d\u0010*\u001a\u00020&8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u001d\u001a\u0004\b(\u0010)R\u001d\u0010.\u001a\u00020\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u001d\u001a\u0004\b,\u0010-R\u001d\u00101\u001a\u00020&8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b/\u0010\u001d\u001a\u0004\b0\u0010)R\u001d\u00106\u001a\u0002028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b3\u0010\u001d\u001a\u0004\b4\u00105R\u001d\u00109\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u001d\u001a\u0004\b8\u0010\u0013R\"\u0010;\u001a\u00020:8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b;\u0010<\u001a\u0004\b;\u0010=\"\u0004\b>\u0010?R\u001d\u0010D\u001a\u00020@8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bA\u0010\u001d\u001a\u0004\bB\u0010CR\u0016\u0010E\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bE\u0010FR\u001d\u0010I\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bG\u0010\u001d\u001a\u0004\bH\u0010$R\u001d\u0010L\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bJ\u0010\u001d\u001a\u0004\bK\u0010$R\u0018\u0010M\u001a\u0004\u0018\u00010:8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bM\u0010<R\u0018\u0010O\u001a\u0004\u0018\u00010N8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bO\u0010PR\u001d\u0010S\u001a\u00020\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bQ\u0010\u001d\u001a\u0004\bR\u0010-R\"\u0010T\u001a\u00020:8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bT\u0010<\u001a\u0004\bU\u0010=\"\u0004\bV\u0010?R\"\u0010W\u001a\u00020:8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bW\u0010<\u001a\u0004\bX\u0010=\"\u0004\bY\u0010?R\u001d\u0010\\\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bZ\u0010\u001d\u001a\u0004\b[\u0010$¨\u0006_"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/topic/PostAIChangeFacePicFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/post/AIViewModel;", "", "restoreDefaultState", "()V", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "adapter", "", "position", "removeItem", "(Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;I)V", "selectImage", "selectImageSource", "uploadImages", "uploadImagesSource", "getLayout", "()I", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/post/AIViewModel;", "onResume", "Landroidx/fragment/app/Fragment;", "childFragment", "onAttachFragment", "(Landroidx/fragment/app/Fragment;)V", "initEvents", "initViews", "Landroid/widget/RadioGroup;", "rg_changeface_open_personal$delegate", "Lkotlin/Lazy;", "getRg_changeface_open_personal", "()Landroid/widget/RadioGroup;", "rg_changeface_open_personal", "Landroid/widget/TextView;", "tv_aichangeface_minface$delegate", "getTv_aichangeface_minface", "()Landroid/widget/TextView;", "tv_aichangeface_minface", "Landroidx/recyclerview/widget/RecyclerView;", "rv_image_base$delegate", "getRv_image_base", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_image_base", "gridSourceImageAdapter$delegate", "getGridSourceImageAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "gridSourceImageAdapter", "rv_image$delegate", "getRv_image", "rv_image", "Landroid/widget/RadioButton;", "rb_aichangeface_open$delegate", "getRb_aichangeface_open", "()Landroid/widget/RadioButton;", "rb_aichangeface_open", "viewModel$delegate", "getViewModel", "viewModel", "", "is_public", "Ljava/lang/String;", "()Ljava/lang/String;", "set_public", "(Ljava/lang/String;)V", "Landroidx/appcompat/widget/AppCompatEditText;", "et_aichangeface_info$delegate", "getEt_aichangeface_info", "()Landroidx/appcompat/widget/AppCompatEditText;", "et_aichangeface_info", "mChosenMediaType", "I", "tv_aichangeface_bottomtips$delegate", "getTv_aichangeface_bottomtips", "tv_aichangeface_bottomtips", "tv_aichangeface_basemin$delegate", "getTv_aichangeface_basemin", "tv_aichangeface_basemin", "mImagePath", "Lc/a/d1;", "jobUploadImages", "Lc/a/d1;", "gridImageAdapter$delegate", "getGridImageAdapter", "gridImageAdapter", "imagesBase", "getImagesBase", "setImagesBase", "images", "getImages", "setImages", "btn_submit_aichangeface_video$delegate", "getBtn_submit_aichangeface_video", "btn_submit_aichangeface_video", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostAIChangeFacePicFragment extends MyThemeViewModelFragment<AIViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: btn_submit_aichangeface_video$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_submit_aichangeface_video;

    /* renamed from: et_aichangeface_info$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy et_aichangeface_info;

    /* renamed from: gridImageAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy gridImageAdapter;

    /* renamed from: gridSourceImageAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy gridSourceImageAdapter;

    @Nullable
    private InterfaceC3053d1 jobUploadImages;
    private int mChosenMediaType;

    @Nullable
    private String mImagePath;

    /* renamed from: rb_aichangeface_open$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rb_aichangeface_open;

    /* renamed from: rg_changeface_open_personal$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rg_changeface_open_personal;

    /* renamed from: rv_image$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_image;

    /* renamed from: rv_image_base$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_image_base;

    /* renamed from: tv_aichangeface_basemin$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_aichangeface_basemin;

    /* renamed from: tv_aichangeface_bottomtips$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_aichangeface_bottomtips;

    /* renamed from: tv_aichangeface_minface$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_aichangeface_minface;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @NotNull
    private String is_public = "y";

    @NotNull
    private String images = "";

    @NotNull
    private String imagesBase = "";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/topic/PostAIChangeFacePicFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/post/topic/PostAIChangeFacePicFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/post/topic/PostAIChangeFacePicFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final PostAIChangeFacePicFragment newInstance() {
            return new PostAIChangeFacePicFragment();
        }
    }

    public PostAIChangeFacePicFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$special$$inlined$viewModels$default$1
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Fragment invoke() {
                return Fragment.this;
            }
        };
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(AIViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$special$$inlined$viewModels$default$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewModelStore invoke() {
                ViewModelStore viewModelStore = ((ViewModelStoreOwner) Function0.this.invoke()).getViewModelStore();
                Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "ownerProducer().viewModelStore");
                return viewModelStore;
            }
        }, null);
        this.btn_submit_aichangeface_video = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$btn_submit_aichangeface_video$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.btn_submit_aichangeface_video);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.gridImageAdapter = LazyKt__LazyJVMKt.lazy(new PostAIChangeFacePicFragment$gridImageAdapter$2(this));
        this.gridSourceImageAdapter = LazyKt__LazyJVMKt.lazy(new PostAIChangeFacePicFragment$gridSourceImageAdapter$2(this));
        this.rv_image = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$rv_image$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_image);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.tv_aichangeface_bottomtips = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$tv_aichangeface_bottomtips$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_aichangeface_bottomtips);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_aichangeface_basemin = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$tv_aichangeface_basemin$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_aichangeface_basemin);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_aichangeface_minface = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$tv_aichangeface_minface$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_aichangeface_minface);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.rv_image_base = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$rv_image_base$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_image_base);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.et_aichangeface_info = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$et_aichangeface_info$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AppCompatEditText invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                AppCompatEditText appCompatEditText = view == null ? null : (AppCompatEditText) view.findViewById(R.id.et_aichangeface_info);
                Intrinsics.checkNotNull(appCompatEditText);
                return appCompatEditText;
            }
        });
        this.rg_changeface_open_personal = LazyKt__LazyJVMKt.lazy(new Function0<RadioGroup>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$rg_changeface_open_personal$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RadioGroup invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                RadioGroup radioGroup = view == null ? null : (RadioGroup) view.findViewById(R.id.rg_changeface_open_personal);
                Intrinsics.checkNotNull(radioGroup);
                return radioGroup;
            }
        });
        this.rb_aichangeface_open = LazyKt__LazyJVMKt.lazy(new Function0<RadioButton>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$rb_aichangeface_open$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RadioButton invoke() {
                View view = PostAIChangeFacePicFragment.this.getView();
                RadioButton radioButton = view == null ? null : (RadioButton) view.findViewById(R.id.rb_aichangeface_open);
                Intrinsics.checkNotNull(radioButton);
                return radioButton;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MediaSelectAdapter getGridImageAdapter() {
        return (MediaSelectAdapter) this.gridImageAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MediaSelectAdapter getGridSourceImageAdapter() {
        return (MediaSelectAdapter) this.gridSourceImageAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initEvents$lambda-4$lambda-3, reason: not valid java name */
    public static final void m5948initEvents$lambda4$lambda3(PostAIChangeFacePicFragment this$0, AIPostConfigsBean aIPostConfigsBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getTv_aichangeface_bottomtips().setText(aIPostConfigsBean.ai_tips);
        TextView tv_aichangeface_basemin = this$0.getTv_aichangeface_basemin();
        StringBuilder m586H = C1499a.m586H("(必填，至少");
        m586H.append((Object) aIPostConfigsBean.ai_change_min_face_num);
        m586H.append("张)");
        tv_aichangeface_basemin.setText(m586H.toString());
        TextView tv_aichangeface_minface = this$0.getTv_aichangeface_minface();
        StringBuilder m586H2 = C1499a.m586H("(必填，至少");
        m586H2.append((Object) aIPostConfigsBean.ai_change_min_num);
        m586H2.append("张)");
        tv_aichangeface_minface.setText(m586H2.toString());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initEvents$lambda-9, reason: not valid java name */
    public static final void m5949initEvents$lambda9(PostAIChangeFacePicFragment this$0, RadioGroup radioGroup, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 == R.id.rb_aichangeface_open) {
            this$0.set_public("y");
        } else {
            this$0.set_public("n");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void removeItem(MediaSelectAdapter adapter, int position) {
        boolean z = true;
        if (this.mChosenMediaType != 1) {
            adapter.remove((MediaSelectAdapter) adapter.getItem(position));
            if (adapter.getData().isEmpty()) {
                adapter.addData((MediaSelectAdapter) new LocalMedia());
                return;
            }
            return;
        }
        if (adapter.getData().size() == 9) {
            String fileName = adapter.getData().get(adapter.getData().size() - 1).getFileName();
            if (fileName != null && fileName.length() != 0) {
                z = false;
            }
            if (!z) {
                adapter.addData((MediaSelectAdapter) new LocalMedia());
            }
        }
        adapter.remove((MediaSelectAdapter) adapter.getItem(position));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void restoreDefaultState() {
        this.mChosenMediaType = 0;
        getRv_image().setVisibility(0);
        this.mImagePath = null;
        getGridImageAdapter().setupMedia(MediaSelectAdapter.MediaType.Image.INSTANCE);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void selectImage() {
        this.mChosenMediaType = this.mChosenMediaType != 2 ? 1 : 2;
        getGridImageAdapter().setupMedia(this.mChosenMediaType == 2 ? MediaSelectAdapter.MediaType.Cover.INSTANCE : MediaSelectAdapter.MediaType.Image.INSTANCE);
        PictureSelectionModel maxSelectNum = PictureSelector.create(this).openGallery(PictureMimeType.ofImage()).imageEngine(C0875w.m204a()).selectionMode(this.mChosenMediaType == 2 ? 1 : 2).maxSelectNum(this.mChosenMediaType == 2 ? 1 : 9);
        List<LocalMedia> data = getGridImageAdapter().getData();
        ArrayList arrayList = new ArrayList();
        for (Object obj : data) {
            String fileName = ((LocalMedia) obj).getFileName();
            if (!(fileName == null || fileName.length() == 0)) {
                arrayList.add(obj);
            }
        }
        maxSelectNum.selectionData(arrayList).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$selectImage$2
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                MediaSelectAdapter gridImageAdapter;
                MediaSelectAdapter gridImageAdapter2;
                MediaSelectAdapter gridImageAdapter3;
                String str;
                MediaSelectAdapter gridImageAdapter4;
                String str2;
                C2818e.m3273b("Image", JSON.toJSONString(result));
                if (result == null || result.isEmpty()) {
                    return;
                }
                PostAIChangeFacePicFragment.this.mImagePath = result.get(0).getRealPath();
                gridImageAdapter = PostAIChangeFacePicFragment.this.getGridImageAdapter();
                gridImageAdapter.replaceData(result);
                gridImageAdapter2 = PostAIChangeFacePicFragment.this.getGridImageAdapter();
                Integer num = null;
                if (gridImageAdapter2.getData().size() < 9) {
                    TextView btn_submit_aichangeface_video = PostAIChangeFacePicFragment.this.getBtn_submit_aichangeface_video();
                    StringBuilder sb = new StringBuilder();
                    gridImageAdapter4 = PostAIChangeFacePicFragment.this.getGridImageAdapter();
                    int size = gridImageAdapter4.getData().size() - 1;
                    AIPostConfigsBean value = PostAIChangeFacePicFragment.this.getViewModel().getAIPostConfigsBean().getValue();
                    if (value != null && (str2 = value.ai_change_price) != null) {
                        num = Integer.valueOf(Integer.parseInt(str2));
                    }
                    Intrinsics.checkNotNull(num);
                    sb.append(num.intValue() * size);
                    sb.append("金币");
                    btn_submit_aichangeface_video.setText(sb.toString());
                    return;
                }
                TextView btn_submit_aichangeface_video2 = PostAIChangeFacePicFragment.this.getBtn_submit_aichangeface_video();
                StringBuilder sb2 = new StringBuilder();
                gridImageAdapter3 = PostAIChangeFacePicFragment.this.getGridImageAdapter();
                int size2 = gridImageAdapter3.getData().size();
                AIPostConfigsBean value2 = PostAIChangeFacePicFragment.this.getViewModel().getAIPostConfigsBean().getValue();
                if (value2 != null && (str = value2.ai_change_price) != null) {
                    num = Integer.valueOf(Integer.parseInt(str));
                }
                Intrinsics.checkNotNull(num);
                sb2.append(num.intValue() * size2);
                sb2.append("金币");
                btn_submit_aichangeface_video2.setText(sb2.toString());
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void selectImageSource() {
        this.mChosenMediaType = this.mChosenMediaType != 2 ? 1 : 2;
        getGridSourceImageAdapter().setupMedia(this.mChosenMediaType == 2 ? MediaSelectAdapter.MediaType.Cover.INSTANCE : MediaSelectAdapter.MediaType.Image.INSTANCE);
        PictureSelectionModel maxSelectNum = PictureSelector.create(this).openGallery(PictureMimeType.ofImage()).imageEngine(C0875w.m204a()).selectionMode(this.mChosenMediaType == 2 ? 1 : 2).maxSelectNum(this.mChosenMediaType == 2 ? 1 : 9);
        List<LocalMedia> data = getGridSourceImageAdapter().getData();
        ArrayList arrayList = new ArrayList();
        for (Object obj : data) {
            String fileName = ((LocalMedia) obj).getFileName();
            if (!(fileName == null || fileName.length() == 0)) {
                arrayList.add(obj);
            }
        }
        maxSelectNum.selectionData(arrayList).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$selectImageSource$2
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                MediaSelectAdapter gridSourceImageAdapter;
                boolean z = true;
                C2818e.m3273b("Image", JSON.toJSONString(result));
                if (result != null && !result.isEmpty()) {
                    z = false;
                }
                if (z) {
                    return;
                }
                PostAIChangeFacePicFragment.this.mImagePath = result.get(0).getRealPath();
                gridSourceImageAdapter = PostAIChangeFacePicFragment.this.getGridSourceImageAdapter();
                gridSourceImageAdapter.replaceData(result);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void uploadImages() {
        showLoadingDialog("正在提交...", true);
        List<LocalMedia> data = getGridImageAdapter().getData();
        ArrayList arrayList = new ArrayList();
        Iterator<T> it = data.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Object next = it.next();
            String realPath = ((LocalMedia) next).getRealPath();
            if (!(realPath == null || realPath.length() == 0)) {
                arrayList.add(next);
            }
        }
        ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(((LocalMedia) it2.next()).getRealPath());
        }
        cancelJob(this.jobUploadImages);
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
        C0949c c0949c = new C0949c(substring, substring2, user_id, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$uploadImages$3
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
                PostAIChangeFacePicFragment.this.hideLoadingDialog();
                C2354n.m2379B1(str5);
            }
        }, "1", null, 32);
        List<LocalMedia> data2 = getGridImageAdapter().getData();
        ArrayList arrayList3 = new ArrayList();
        for (Object obj : data2) {
            String realPath2 = ((LocalMedia) obj).getRealPath();
            if (!(realPath2 == null || realPath2.length() == 0)) {
                arrayList3.add(obj);
            }
        }
        ArrayList arrayList4 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList3, 10));
        Iterator it3 = arrayList3.iterator();
        while (it3.hasNext()) {
            arrayList4.add(((LocalMedia) it3.next()).getRealPath());
        }
        this.jobUploadImages = c0949c.m292c(arrayList4, new Function1<ArrayList<UploadPicResponse.DataBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$uploadImages$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ArrayList<UploadPicResponse.DataBean> arrayList5) {
                invoke2(arrayList5);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ArrayList<UploadPicResponse.DataBean> result) {
                Intrinsics.checkNotNullParameter(result, "result");
                PostAIChangeFacePicFragment postAIChangeFacePicFragment = PostAIChangeFacePicFragment.this;
                Iterator<T> it4 = result.iterator();
                while (it4.hasNext()) {
                    postAIChangeFacePicFragment.setImages(postAIChangeFacePicFragment.getImages() + ((UploadPicResponse.DataBean) it4.next()).getFile() + ',');
                }
                PostAIChangeFacePicFragment postAIChangeFacePicFragment2 = PostAIChangeFacePicFragment.this;
                String substring3 = postAIChangeFacePicFragment2.getImages().substring(0, PostAIChangeFacePicFragment.this.getImages().length() - 1);
                Intrinsics.checkNotNullExpressionValue(substring3, "this as java.lang.String…ing(startIndex, endIndex)");
                postAIChangeFacePicFragment2.setImages(substring3);
                PostAIChangeFacePicFragment.this.uploadImagesSource();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void uploadImagesSource() {
        List<LocalMedia> data = getGridSourceImageAdapter().getData();
        ArrayList arrayList = new ArrayList();
        Iterator<T> it = data.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Object next = it.next();
            String realPath = ((LocalMedia) next).getRealPath();
            if (!(realPath == null || realPath.length() == 0)) {
                arrayList.add(next);
            }
        }
        ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(((LocalMedia) it2.next()).getRealPath());
        }
        cancelJob(this.jobUploadImages);
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
        C0949c c0949c = new C0949c(substring, substring2, user_id, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$uploadImagesSource$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str5) {
                invoke2(str5);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str5) {
                C2354n.m2379B1(str5);
            }
        }, "1", null, 32);
        List<LocalMedia> data2 = getGridSourceImageAdapter().getData();
        ArrayList arrayList3 = new ArrayList();
        for (Object obj : data2) {
            String realPath2 = ((LocalMedia) obj).getRealPath();
            if (!(realPath2 == null || realPath2.length() == 0)) {
                arrayList3.add(obj);
            }
        }
        ArrayList arrayList4 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList3, 10));
        Iterator it3 = arrayList3.iterator();
        while (it3.hasNext()) {
            arrayList4.add(((LocalMedia) it3.next()).getRealPath());
        }
        this.jobUploadImages = c0949c.m292c(arrayList4, new Function1<ArrayList<UploadPicResponse.DataBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$uploadImagesSource$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ArrayList<UploadPicResponse.DataBean> arrayList5) {
                invoke2(arrayList5);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ArrayList<UploadPicResponse.DataBean> result) {
                Intrinsics.checkNotNullParameter(result, "result");
                PostAIChangeFacePicFragment postAIChangeFacePicFragment = PostAIChangeFacePicFragment.this;
                Iterator<T> it4 = result.iterator();
                while (it4.hasNext()) {
                    postAIChangeFacePicFragment.setImagesBase(postAIChangeFacePicFragment.getImagesBase() + ((UploadPicResponse.DataBean) it4.next()).getFile() + ',');
                }
                PostAIChangeFacePicFragment postAIChangeFacePicFragment2 = PostAIChangeFacePicFragment.this;
                String substring3 = postAIChangeFacePicFragment2.getImagesBase().substring(0, PostAIChangeFacePicFragment.this.getImagesBase().length() - 1);
                Intrinsics.checkNotNullExpressionValue(substring3, "this as java.lang.String…ing(startIndex, endIndex)");
                postAIChangeFacePicFragment2.setImagesBase(substring3);
                AIViewModel viewModel = PostAIChangeFacePicFragment.this.getViewModel();
                String obj2 = StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAIChangeFacePicFragment.this.getEt_aichangeface_info().getText())).toString();
                String images = PostAIChangeFacePicFragment.this.getImages();
                String imagesBase = PostAIChangeFacePicFragment.this.getImagesBase();
                String is_public = PostAIChangeFacePicFragment.this.getIs_public();
                final PostAIChangeFacePicFragment postAIChangeFacePicFragment3 = PostAIChangeFacePicFragment.this;
                viewModel.postDoChange(obj2, images, imagesBase, is_public, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$uploadImagesSource$6.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        PostAIChangeFacePicFragment.this.hideLoadingDialog();
                        if (z) {
                            MyBoughtActivity.Companion companion = MyBoughtActivity.INSTANCE;
                            Context requireContext = PostAIChangeFacePicFragment.this.requireContext();
                            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                            companion.start(requireContext, 3);
                            FragmentActivity activity = PostAIChangeFacePicFragment.this.getActivity();
                            if (activity == null) {
                                return;
                            }
                            activity.finish();
                        }
                    }
                });
            }
        });
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final TextView getBtn_submit_aichangeface_video() {
        return (TextView) this.btn_submit_aichangeface_video.getValue();
    }

    @NotNull
    public final AppCompatEditText getEt_aichangeface_info() {
        return (AppCompatEditText) this.et_aichangeface_info.getValue();
    }

    @NotNull
    public final String getImages() {
        return this.images;
    }

    @NotNull
    public final String getImagesBase() {
        return this.imagesBase;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_aichangeface;
    }

    @NotNull
    public final RadioButton getRb_aichangeface_open() {
        return (RadioButton) this.rb_aichangeface_open.getValue();
    }

    @NotNull
    public final RadioGroup getRg_changeface_open_personal() {
        return (RadioGroup) this.rg_changeface_open_personal.getValue();
    }

    @NotNull
    public final RecyclerView getRv_image() {
        return (RecyclerView) this.rv_image.getValue();
    }

    @NotNull
    public final RecyclerView getRv_image_base() {
        return (RecyclerView) this.rv_image_base.getValue();
    }

    @NotNull
    public final TextView getTv_aichangeface_basemin() {
        return (TextView) this.tv_aichangeface_basemin.getValue();
    }

    @NotNull
    public final TextView getTv_aichangeface_bottomtips() {
        return (TextView) this.tv_aichangeface_bottomtips.getValue();
    }

    @NotNull
    public final TextView getTv_aichangeface_minface() {
        return (TextView) this.tv_aichangeface_minface.getValue();
    }

    @NotNull
    public final AIViewModel getViewModel() {
        return (AIViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    @SuppressLint({"UseSwitchCompatOrMaterialCode"})
    public void initEvents() {
        super.initEvents();
        getViewModel().postAiConfigs();
        getViewModel().getAIPostConfigsBean().observe(this, new Observer() { // from class: b.a.a.a.t.k.f.b
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PostAIChangeFacePicFragment.m5948initEvents$lambda4$lambda3(PostAIChangeFacePicFragment.this, (AIPostConfigsBean) obj);
            }
        });
        RecyclerView rv_image = getRv_image();
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        rv_image.setLayoutManager(new GridLayoutManager(applicationC2828a, 3));
        if (rv_image.getItemDecorationCount() == 0) {
            ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
            if (applicationC2828a2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(applicationC2828a2);
            c4053a.m4576a(R.color.transparent);
            ApplicationC2828a applicationC2828a3 = C2827a.f7670a;
            if (applicationC2828a3 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            c4053a.f10336d = C2354n.m2437V(applicationC2828a3, 8.0d);
            ApplicationC2828a applicationC2828a4 = C2827a.f7670a;
            if (applicationC2828a4 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            c4053a.f10337e = C2354n.m2437V(applicationC2828a4, 8.0d);
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            c4053a.f10339g = false;
            rv_image.addItemDecoration(new GridItemDecoration(c4053a));
        }
        MediaSelectAdapter gridImageAdapter = getGridImageAdapter();
        gridImageAdapter.addData((MediaSelectAdapter) new LocalMedia());
        Unit unit = Unit.INSTANCE;
        rv_image.setAdapter(gridImageAdapter);
        RecyclerView rv_image_base = getRv_image_base();
        ApplicationC2828a applicationC2828a5 = C2827a.f7670a;
        if (applicationC2828a5 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        rv_image_base.setLayoutManager(new GridLayoutManager(applicationC2828a5, 3));
        if (rv_image_base.getItemDecorationCount() == 0) {
            ApplicationC2828a applicationC2828a6 = C2827a.f7670a;
            if (applicationC2828a6 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(applicationC2828a6);
            c4053a2.m4576a(R.color.transparent);
            ApplicationC2828a applicationC2828a7 = C2827a.f7670a;
            if (applicationC2828a7 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            c4053a2.f10336d = C2354n.m2437V(applicationC2828a7, 8.0d);
            ApplicationC2828a applicationC2828a8 = C2827a.f7670a;
            if (applicationC2828a8 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            c4053a2.f10337e = C2354n.m2437V(applicationC2828a8, 8.0d);
            c4053a2.f10340h = false;
            c4053a2.f10338f = false;
            c4053a2.f10339g = false;
            rv_image_base.addItemDecoration(new GridItemDecoration(c4053a2));
        }
        MediaSelectAdapter gridSourceImageAdapter = getGridSourceImageAdapter();
        gridSourceImageAdapter.addData((MediaSelectAdapter) new LocalMedia());
        rv_image_base.setAdapter(gridSourceImageAdapter);
        C2354n.m2374A(getBtn_submit_aichangeface_video(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAIChangeFacePicFragment$initEvents$4
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
                MediaSelectAdapter gridImageAdapter2;
                MediaSelectAdapter gridSourceImageAdapter2;
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAIChangeFacePicFragment.this.getEt_aichangeface_info().getText())).toString(), "")) {
                    C2354n.m2525w0("请输入描述内容");
                    return;
                }
                gridImageAdapter2 = PostAIChangeFacePicFragment.this.getGridImageAdapter();
                if (gridImageAdapter2.getData().size() == 1) {
                    C2354n.m2525w0("上传人脸参考照片");
                    return;
                }
                gridSourceImageAdapter2 = PostAIChangeFacePicFragment.this.getGridSourceImageAdapter();
                if (gridSourceImageAdapter2.getData().size() == 1) {
                    C2354n.m2525w0("上传人脸原图照片");
                } else {
                    PostAIChangeFacePicFragment.this.uploadImages();
                }
            }
        }, 1);
        getRg_changeface_open_personal().setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: b.a.a.a.t.k.f.a
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup, int i2) {
                PostAIChangeFacePicFragment.m5949initEvents$lambda9(PostAIChangeFacePicFragment.this, radioGroup, i2);
            }
        });
        getViewModel();
        getRb_aichangeface_open().setChecked(true);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
    }

    @NotNull
    /* renamed from: is_public, reason: from getter */
    public final String getIs_public() {
        return this.is_public;
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttachFragment(@NotNull Fragment childFragment) {
        Intrinsics.checkNotNullParameter(childFragment, "childFragment");
        super.onAttachFragment(childFragment);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
    }

    public final void setImages(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.images = str;
    }

    public final void setImagesBase(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.imagesBase = str;
    }

    public final void set_public(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.is_public = str;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public AIViewModel viewModelInstance() {
        return getViewModel();
    }
}

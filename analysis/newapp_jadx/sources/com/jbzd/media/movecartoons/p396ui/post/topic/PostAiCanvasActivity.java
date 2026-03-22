package com.jbzd.media.movecartoons.p396ui.post.topic;

import android.content.Context;
import android.widget.RadioGroup;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.alibaba.fastjson.JSON;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.UploadPicResponse;
import com.jbzd.media.movecartoons.bean.response.AIPostConfigsBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.trade.MediaSelectAdapter;
import com.jbzd.media.movecartoons.p396ui.post.AIViewModel;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostAiCanvasActivity;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0016\u0018\u0000 K2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001KB\u0007¢\u0006\u0004\bJ\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0005J\u001f\u0010\u000b\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\tH\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\r\u0010\u0005J\u000f\u0010\u000e\u001a\u00020\tH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0010\u0010\u0005J\u000f\u0010\u0012\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0012\u0010\u0013J\u000f\u0010\u0014\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0014\u0010\u0013J\u000f\u0010\u0015\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0015\u0010\u0005J\r\u0010\u0016\u001a\u00020\u0002¢\u0006\u0004\b\u0016\u0010\u0017R\u001d\u0010\u001d\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\u0018\u0010\u001e\u001a\u0004\u0018\u00010\u00118\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001e\u0010\u001fR\u001d\u0010\"\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u001a\u001a\u0004\b!\u0010\u0017R\u0018\u0010$\u001a\u0004\u0018\u00010#8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b$\u0010%R\u001d\u0010)\u001a\u00020\u00078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u001a\u001a\u0004\b'\u0010(R\u001d\u0010.\u001a\u00020*8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u001a\u001a\u0004\b,\u0010-R\u0016\u0010/\u001a\u00020\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b/\u00100R\u001d\u00105\u001a\u0002018F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b2\u0010\u001a\u001a\u0004\b3\u00104R\u001d\u0010:\u001a\u0002068F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u001a\u001a\u0004\b8\u00109R\"\u0010;\u001a\u00020\u00118\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b;\u0010\u001f\u001a\u0004\b<\u0010\u0013\"\u0004\b=\u0010>R\u001d\u0010A\u001a\u00020*8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u001a\u001a\u0004\b@\u0010-R\u001d\u0010D\u001a\u00020*8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bB\u0010\u001a\u001a\u0004\bC\u0010-R\u001d\u0010G\u001a\u0002068F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u001a\u001a\u0004\bF\u00109R\"\u0010H\u001a\u00020\u00118\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bH\u0010\u001f\u001a\u0004\bH\u0010\u0013\"\u0004\bI\u0010>¨\u0006L"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/topic/PostAiCanvasActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/post/AIViewModel;", "", "uploadImages", "()V", "restoreDefaultState", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "adapter", "", "position", "removeItem", "(Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;I)V", "selectImage", "getLayoutId", "()I", "bindEvent", "", "getTopBarTitle", "()Ljava/lang/String;", "getRightTitle", "clickRight", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/post/AIViewModel;", "Landroidx/recyclerview/widget/RecyclerView;", "rv_image_base$delegate", "Lkotlin/Lazy;", "getRv_image_base", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_image_base", "mImagePath", "Ljava/lang/String;", "viewModel$delegate", "getViewModel", "viewModel", "Lc/a/d1;", "jobUploadImages", "Lc/a/d1;", "gridImageAdapter$delegate", "getGridImageAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "gridImageAdapter", "Landroid/widget/TextView;", "tv_aicanvas_bottomtips$delegate", "getTv_aicanvas_bottomtips", "()Landroid/widget/TextView;", "tv_aicanvas_bottomtips", "mChosenMediaType", "I", "Landroid/widget/RadioGroup;", "rg_posttype_open_personal$delegate", "getRg_posttype_open_personal", "()Landroid/widget/RadioGroup;", "rg_posttype_open_personal", "Landroidx/appcompat/widget/AppCompatEditText;", "et_input_number$delegate", "getEt_input_number", "()Landroidx/appcompat/widget/AppCompatEditText;", "et_input_number", "imagesBase", "getImagesBase", "setImagesBase", "(Ljava/lang/String;)V", "btn_submit_aicanvas$delegate", "getBtn_submit_aicanvas", "btn_submit_aicanvas", "tv_oneunit_pic_num$delegate", "getTv_oneunit_pic_num", "tv_oneunit_pic_num", "et_aicanvas_content$delegate", "getEt_aicanvas_content", "et_aicanvas_content", "is_public", "set_public", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostAiCanvasActivity extends MyThemeActivity<AIViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private InterfaceC3053d1 jobUploadImages;
    private int mChosenMediaType;

    @Nullable
    private String mImagePath;

    @NotNull
    private String is_public = "y";

    @NotNull
    private String imagesBase = "";

    /* renamed from: tv_aicanvas_bottomtips$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_aicanvas_bottomtips = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$tv_aicanvas_bottomtips$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostAiCanvasActivity.this.findViewById(R.id.tv_aicanvas_bottomtips);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: rv_image_base$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_image_base = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$rv_image_base$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) PostAiCanvasActivity.this.findViewById(R.id.rv_image_base);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: tv_oneunit_pic_num$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_oneunit_pic_num = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$tv_oneunit_pic_num$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostAiCanvasActivity.this.findViewById(R.id.tv_oneunit_pic_num);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: rg_posttype_open_personal$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rg_posttype_open_personal = LazyKt__LazyJVMKt.lazy(new Function0<RadioGroup>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$rg_posttype_open_personal$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RadioGroup invoke() {
            RadioGroup radioGroup = (RadioGroup) PostAiCanvasActivity.this.findViewById(R.id.rg_posttype_open_personal);
            Intrinsics.checkNotNull(radioGroup);
            return radioGroup;
        }
    });

    /* renamed from: btn_submit_aicanvas$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_submit_aicanvas = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$btn_submit_aicanvas$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostAiCanvasActivity.this.findViewById(R.id.btn_submit_aicanvas);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: et_aicanvas_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy et_aicanvas_content = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$et_aicanvas_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatEditText invoke() {
            AppCompatEditText appCompatEditText = (AppCompatEditText) PostAiCanvasActivity.this.findViewById(R.id.et_aicanvas_content);
            Intrinsics.checkNotNull(appCompatEditText);
            return appCompatEditText;
        }
    });

    /* renamed from: et_input_number$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy et_input_number = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$et_input_number$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatEditText invoke() {
            AppCompatEditText appCompatEditText = (AppCompatEditText) PostAiCanvasActivity.this.findViewById(R.id.et_input_number);
            Intrinsics.checkNotNull(appCompatEditText);
            return appCompatEditText;
        }
    });

    /* renamed from: gridImageAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy gridImageAdapter = LazyKt__LazyJVMKt.lazy(new PostAiCanvasActivity$gridImageAdapter$2(this));

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(AIViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$special$$inlined$viewModels$default$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelStore invoke() {
            ViewModelStore viewModelStore = ComponentActivity.this.getViewModelStore();
            Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "viewModelStore");
            return viewModelStore;
        }
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$special$$inlined$viewModels$default$1
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelProvider.Factory invoke() {
            ViewModelProvider.Factory defaultViewModelProviderFactory = ComponentActivity.this.getDefaultViewModelProviderFactory();
            Intrinsics.checkExpressionValueIsNotNull(defaultViewModelProviderFactory, "defaultViewModelProviderFactory");
            return defaultViewModelProviderFactory;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/topic/PostAiCanvasActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, PostAiCanvasActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5954bindEvent$lambda1$lambda0(PostAiCanvasActivity this$0, AIPostConfigsBean aIPostConfigsBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getTv_aicanvas_bottomtips().setText(aIPostConfigsBean.ai_tips);
        TextView tv_oneunit_pic_num = this$0.getTv_oneunit_pic_num();
        StringBuilder m586H = C1499a.m586H("(必填，一套图");
        m586H.append((Object) aIPostConfigsBean.ai_huihua_max_num);
        m586H.append("张)");
        tv_oneunit_pic_num.setText(m586H.toString());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-4, reason: not valid java name */
    public static final void m5955bindEvent$lambda4(PostAiCanvasActivity this$0, RadioGroup radioGroup, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 == R.id.rb_aiclear_open) {
            this$0.set_public("y");
        } else {
            this$0.set_public("n");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MediaSelectAdapter getGridImageAdapter() {
        return (MediaSelectAdapter) this.gridImageAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AIViewModel getViewModel() {
        return (AIViewModel) this.viewModel.getValue();
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
        getRv_image_base().setVisibility(0);
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
        maxSelectNum.selectionData(arrayList).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$selectImage$2
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                MediaSelectAdapter gridImageAdapter;
                MediaSelectAdapter gridImageAdapter2;
                MediaSelectAdapter gridImageAdapter3;
                AIViewModel viewModel;
                String str;
                MediaSelectAdapter gridImageAdapter4;
                AIViewModel viewModel2;
                String str2;
                C2818e.m3273b("Image", JSON.toJSONString(result));
                if (result == null || result.isEmpty()) {
                    return;
                }
                PostAiCanvasActivity.this.mImagePath = result.get(0).getRealPath();
                gridImageAdapter = PostAiCanvasActivity.this.getGridImageAdapter();
                gridImageAdapter.replaceData(result);
                gridImageAdapter2 = PostAiCanvasActivity.this.getGridImageAdapter();
                Integer num = null;
                if (gridImageAdapter2.getData().size() < 9) {
                    TextView btn_submit_aicanvas = PostAiCanvasActivity.this.getBtn_submit_aicanvas();
                    StringBuilder sb = new StringBuilder();
                    gridImageAdapter4 = PostAiCanvasActivity.this.getGridImageAdapter();
                    int size = gridImageAdapter4.getData().size() - 1;
                    viewModel2 = PostAiCanvasActivity.this.getViewModel();
                    AIPostConfigsBean value = viewModel2.getAIPostConfigsBean().getValue();
                    if (value != null && (str2 = value.ai_huihua_price) != null) {
                        num = Integer.valueOf(Integer.parseInt(str2));
                    }
                    Intrinsics.checkNotNull(num);
                    sb.append(num.intValue() * size);
                    sb.append("金币");
                    btn_submit_aicanvas.setText(sb.toString());
                    return;
                }
                TextView btn_submit_aicanvas2 = PostAiCanvasActivity.this.getBtn_submit_aicanvas();
                StringBuilder sb2 = new StringBuilder();
                gridImageAdapter3 = PostAiCanvasActivity.this.getGridImageAdapter();
                int size2 = gridImageAdapter3.getData().size();
                viewModel = PostAiCanvasActivity.this.getViewModel();
                AIPostConfigsBean value2 = viewModel.getAIPostConfigsBean().getValue();
                if (value2 != null && (str = value2.ai_huihua_price) != null) {
                    num = Integer.valueOf(Integer.parseInt(str));
                }
                Intrinsics.checkNotNull(num);
                sb2.append(num.intValue() * size2);
                sb2.append("金币");
                btn_submit_aicanvas2.setText(sb2.toString());
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
        C0949c c0949c = new C0949c(substring, substring2, user_id, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$uploadImages$3
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
        this.jobUploadImages = c0949c.m292c(arrayList4, new Function1<ArrayList<UploadPicResponse.DataBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$uploadImages$6
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
                AIViewModel viewModel;
                Intrinsics.checkNotNullParameter(result, "result");
                PostAiCanvasActivity postAiCanvasActivity = PostAiCanvasActivity.this;
                Iterator<T> it4 = result.iterator();
                while (it4.hasNext()) {
                    postAiCanvasActivity.setImagesBase(postAiCanvasActivity.getImagesBase() + ((UploadPicResponse.DataBean) it4.next()).getFile() + ',');
                }
                PostAiCanvasActivity postAiCanvasActivity2 = PostAiCanvasActivity.this;
                String substring3 = postAiCanvasActivity2.getImagesBase().substring(0, PostAiCanvasActivity.this.getImagesBase().length() - 1);
                Intrinsics.checkNotNullExpressionValue(substring3, "this as java.lang.String…ing(startIndex, endIndex)");
                postAiCanvasActivity2.setImagesBase(substring3);
                viewModel = PostAiCanvasActivity.this.getViewModel();
                String obj2 = StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAiCanvasActivity.this.getEt_aicanvas_content().getText())).toString();
                String imagesBase = PostAiCanvasActivity.this.getImagesBase();
                String obj3 = StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAiCanvasActivity.this.getEt_input_number().getText())).toString();
                String is_public = PostAiCanvasActivity.this.getIs_public();
                final PostAiCanvasActivity postAiCanvasActivity3 = PostAiCanvasActivity.this;
                viewModel.postDoHuihua(obj2, imagesBase, obj3, is_public, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$uploadImages$6.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        PostAiCanvasActivity.this.hideLoadingDialog();
                        if (z) {
                            MyBoughtActivity.INSTANCE.start(PostAiCanvasActivity.this, 3);
                            PostAiCanvasActivity.this.finish();
                        }
                    }
                });
            }
        });
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getViewModel().postAiConfigs();
        getViewModel().getAIPostConfigsBean().observe(this, new Observer() { // from class: b.a.a.a.t.k.f.g
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PostAiCanvasActivity.m5954bindEvent$lambda1$lambda0(PostAiCanvasActivity.this, (AIPostConfigsBean) obj);
            }
        });
        RecyclerView rv_image_base = getRv_image_base();
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        rv_image_base.setLayoutManager(new GridLayoutManager(applicationC2828a, 3));
        if (rv_image_base.getItemDecorationCount() == 0) {
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
            rv_image_base.addItemDecoration(new GridItemDecoration(c4053a));
        }
        MediaSelectAdapter gridImageAdapter = getGridImageAdapter();
        gridImageAdapter.addData((MediaSelectAdapter) new LocalMedia());
        Unit unit = Unit.INSTANCE;
        rv_image_base.setAdapter(gridImageAdapter);
        getRg_posttype_open_personal().setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: b.a.a.a.t.k.f.h
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup, int i2) {
                PostAiCanvasActivity.m5955bindEvent$lambda4(PostAiCanvasActivity.this, radioGroup, i2);
            }
        });
        C2354n.m2374A(getBtn_submit_aicanvas(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiCanvasActivity$bindEvent$4
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
                MediaSelectAdapter gridImageAdapter3;
                AIViewModel viewModel;
                AIViewModel viewModel2;
                String str;
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAiCanvasActivity.this.getEt_aicanvas_content().getText())).toString(), "")) {
                    C2354n.m2525w0("请输入描述内容");
                    return;
                }
                gridImageAdapter2 = PostAiCanvasActivity.this.getGridImageAdapter();
                if (gridImageAdapter2.getData().size() < 2) {
                    C2354n.m2525w0("请上传人脸参考照片");
                    return;
                }
                gridImageAdapter3 = PostAiCanvasActivity.this.getGridImageAdapter();
                int size = gridImageAdapter3.getData().size();
                viewModel = PostAiCanvasActivity.this.getViewModel();
                AIPostConfigsBean value = viewModel.getAIPostConfigsBean().getValue();
                Integer valueOf = (value == null || (str = value.ai_huihua_max_num) == null) ? null : Integer.valueOf(Integer.parseInt(str));
                Intrinsics.checkNotNull(valueOf);
                if (size >= valueOf.intValue()) {
                    if (Intrinsics.areEqual(StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAiCanvasActivity.this.getEt_input_number().getText())).toString(), "") || Intrinsics.areEqual(StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAiCanvasActivity.this.getEt_input_number().getText())).toString(), "0")) {
                        C2354n.m2525w0("请输入绘画套数");
                        return;
                    } else {
                        PostAiCanvasActivity.this.uploadImages();
                        return;
                    }
                }
                StringBuilder m586H = C1499a.m586H("请上传");
                viewModel2 = PostAiCanvasActivity.this.getViewModel();
                AIPostConfigsBean value2 = viewModel2.getAIPostConfigsBean().getValue();
                m586H.append((Object) (value2 != null ? value2.ai_huihua_max_num : null));
                m586H.append("张照片");
                C2354n.m2525w0(m586H.toString());
            }
        }, 1);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void clickRight() {
    }

    @NotNull
    public final TextView getBtn_submit_aicanvas() {
        return (TextView) this.btn_submit_aicanvas.getValue();
    }

    @NotNull
    public final AppCompatEditText getEt_aicanvas_content() {
        return (AppCompatEditText) this.et_aicanvas_content.getValue();
    }

    @NotNull
    public final AppCompatEditText getEt_input_number() {
        return (AppCompatEditText) this.et_input_number.getValue();
    }

    @NotNull
    public final String getImagesBase() {
        return this.imagesBase;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_post_aicanvas;
    }

    @NotNull
    public final RadioGroup getRg_posttype_open_personal() {
        return (RadioGroup) this.rg_posttype_open_personal.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getRightTitle() {
        return "";
    }

    @NotNull
    public final RecyclerView getRv_image_base() {
        return (RecyclerView) this.rv_image_base.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "AI绘画";
    }

    @NotNull
    public final TextView getTv_aicanvas_bottomtips() {
        return (TextView) this.tv_aicanvas_bottomtips.getValue();
    }

    @NotNull
    public final TextView getTv_oneunit_pic_num() {
        return (TextView) this.tv_oneunit_pic_num.getValue();
    }

    @NotNull
    /* renamed from: is_public, reason: from getter */
    public final String getIs_public() {
        return this.is_public;
    }

    public final void setImagesBase(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.imagesBase = str;
    }

    public final void set_public(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.is_public = str;
    }

    @NotNull
    public final AIViewModel viewModelInstance() {
        return getViewModel();
    }
}

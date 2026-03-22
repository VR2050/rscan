package com.jbzd.media.movecartoons.p396ui.post.topic;

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
import com.jbzd.media.movecartoons.p396ui.index.darkplay.BaseVideoItemFragment;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.trade.MediaSelectAdapter;
import com.jbzd.media.movecartoons.p396ui.post.AIViewModel;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostAiChangeFaceVideoFragment;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000`\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\f\u0018\u0000 M2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001MB\u0007¢\u0006\u0004\bL\u0010\u000bJ\u001f\u0010\b\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\f\u0010\u000bJ\u000f\u0010\r\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\r\u0010\u000bJ\u000f\u0010\u000e\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\u0010\u0010\u000bJ\u0017\u0010\u0013\u001a\u00020\u00072\u0006\u0010\u0012\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\u0017\u0010\u000bJ\u000f\u0010\u0018\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\u0018\u0010\u000bR\u001d\u0010\u001e\u001a\u00020\u00198F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u001b\u001a\u0004\b\u001c\u0010\u001dR\u001d\u0010!\u001a\u00020\u00198F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u001b\u001a\u0004\b \u0010\u001dR\u001d\u0010&\u001a\u00020\"8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u001b\u001a\u0004\b$\u0010%R\u001d\u0010+\u001a\u00020'8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u001b\u001a\u0004\b)\u0010*R\u0018\u0010-\u001a\u0004\u0018\u00010,8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b-\u0010.R\u0016\u00100\u001a\u00020/8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b0\u00101R\u001d\u00106\u001a\u0002028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b3\u0010\u001b\u001a\u0004\b4\u00105R\u0016\u00107\u001a\u00020/8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b7\u00101R\u0016\u00108\u001a\u00020\u00058\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b8\u00109R\u0016\u0010:\u001a\u00020/8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b:\u00101R\u001d\u0010=\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b;\u0010\u001b\u001a\u0004\b<\u0010\u000fR\u001d\u0010A\u001a\u00020\u00038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b>\u0010\u001b\u001a\u0004\b?\u0010@R\u001d\u0010F\u001a\u00020B8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bC\u0010\u001b\u001a\u0004\bD\u0010ER\u0016\u0010G\u001a\u00020/8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bG\u00101R\u001d\u0010J\u001a\u00020\u00198F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bH\u0010\u001b\u001a\u0004\bI\u0010\u001dR\u0018\u0010K\u001a\u0004\u0018\u00010/8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bK\u00101¨\u0006N"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/topic/PostAiChangeFaceVideoFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/post/AIViewModel;", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "adapter", "", "position", "", "removeItem", "(Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;I)V", "restoreDefaultState", "()V", "selectImage", "uploadImages", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/post/AIViewModel;", "onResume", "Landroidx/fragment/app/Fragment;", "childFragment", "onAttachFragment", "(Landroidx/fragment/app/Fragment;)V", "getLayout", "()I", "initEvents", "initViews", "Landroid/widget/TextView;", "tv_aivideo_changeface_bottomtips$delegate", "Lkotlin/Lazy;", "getTv_aivideo_changeface_bottomtips", "()Landroid/widget/TextView;", "tv_aivideo_changeface_bottomtips", "btn_submit_aichangeface_video$delegate", "getBtn_submit_aichangeface_video", "btn_submit_aichangeface_video", "Landroid/widget/RadioGroup;", "rg_aivideochangeface_open_private$delegate", "getRg_aivideochangeface_open_private", "()Landroid/widget/RadioGroup;", "rg_aivideochangeface_open_private", "Landroidx/appcompat/widget/AppCompatEditText;", "et_aivideochangeface_info$delegate", "getEt_aivideochangeface_info", "()Landroidx/appcompat/widget/AppCompatEditText;", "et_aivideochangeface_info", "Lc/a/d1;", "jobUploadImages", "Lc/a/d1;", "", "is_public", "Ljava/lang/String;", "Landroid/widget/RadioButton;", "rb_aivideochange_open$delegate", "getRb_aivideochange_open", "()Landroid/widget/RadioButton;", "rb_aivideochange_open", "imagesBase", "mChosenMediaType", "I", "video_image", "viewModel$delegate", "getViewModel", "viewModel", "gridImageAdapter$delegate", "getGridImageAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "gridImageAdapter", "Landroidx/recyclerview/widget/RecyclerView;", "rv_image_base$delegate", "getRv_image_base", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_image_base", "video_value", "tv_aivideo_changeface_minnum$delegate", "getTv_aivideo_changeface_minnum", "tv_aivideo_changeface_minnum", "mImagePath", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostAiChangeFaceVideoFragment extends MyThemeViewModelFragment<AIViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: btn_submit_aichangeface_video$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_submit_aichangeface_video;

    /* renamed from: et_aivideochangeface_info$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy et_aivideochangeface_info;

    /* renamed from: gridImageAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy gridImageAdapter;

    @Nullable
    private InterfaceC3053d1 jobUploadImages;
    private int mChosenMediaType;

    @Nullable
    private String mImagePath;

    /* renamed from: rb_aivideochange_open$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rb_aivideochange_open;

    /* renamed from: rg_aivideochangeface_open_private$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rg_aivideochangeface_open_private;

    /* renamed from: rv_image_base$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_image_base;

    /* renamed from: tv_aivideo_changeface_bottomtips$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_aivideo_changeface_bottomtips;

    /* renamed from: tv_aivideo_changeface_minnum$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_aivideo_changeface_minnum;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @NotNull
    private String is_public = "y";

    @NotNull
    private String video_image = "";

    @NotNull
    private String video_value = "";

    @NotNull
    private String imagesBase = "";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/topic/PostAiChangeFaceVideoFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/post/topic/PostAiChangeFaceVideoFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/post/topic/PostAiChangeFaceVideoFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final PostAiChangeFaceVideoFragment newInstance() {
            return new PostAiChangeFaceVideoFragment();
        }
    }

    public PostAiChangeFaceVideoFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$special$$inlined$viewModels$default$1
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
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(AIViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$special$$inlined$viewModels$default$2
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
        this.btn_submit_aichangeface_video = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$btn_submit_aichangeface_video$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = PostAiChangeFaceVideoFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.btn_submit_aichangeface_video);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.gridImageAdapter = LazyKt__LazyJVMKt.lazy(new PostAiChangeFaceVideoFragment$gridImageAdapter$2(this));
        this.rv_image_base = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$rv_image_base$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = PostAiChangeFaceVideoFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_image_base);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.et_aivideochangeface_info = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$et_aivideochangeface_info$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AppCompatEditText invoke() {
                View view = PostAiChangeFaceVideoFragment.this.getView();
                AppCompatEditText appCompatEditText = view == null ? null : (AppCompatEditText) view.findViewById(R.id.et_aivideochangeface_info);
                Intrinsics.checkNotNull(appCompatEditText);
                return appCompatEditText;
            }
        });
        this.rg_aivideochangeface_open_private = LazyKt__LazyJVMKt.lazy(new Function0<RadioGroup>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$rg_aivideochangeface_open_private$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RadioGroup invoke() {
                View view = PostAiChangeFaceVideoFragment.this.getView();
                RadioGroup radioGroup = view == null ? null : (RadioGroup) view.findViewById(R.id.rg_aivideochangeface_open_private);
                Intrinsics.checkNotNull(radioGroup);
                return radioGroup;
            }
        });
        this.rb_aivideochange_open = LazyKt__LazyJVMKt.lazy(new Function0<RadioButton>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$rb_aivideochange_open$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RadioButton invoke() {
                View view = PostAiChangeFaceVideoFragment.this.getView();
                RadioButton radioButton = view == null ? null : (RadioButton) view.findViewById(R.id.rb_aivideochange_open);
                Intrinsics.checkNotNull(radioButton);
                return radioButton;
            }
        });
        this.tv_aivideo_changeface_bottomtips = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$tv_aivideo_changeface_bottomtips$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = PostAiChangeFaceVideoFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_aivideo_changeface_bottomtips);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_aivideo_changeface_minnum = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$tv_aivideo_changeface_minnum$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = PostAiChangeFaceVideoFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_aivideo_changeface_minnum);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MediaSelectAdapter getGridImageAdapter() {
        return (MediaSelectAdapter) this.gridImageAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initEvents$lambda-4, reason: not valid java name */
    public static final void m5958initEvents$lambda4(PostAiChangeFaceVideoFragment this$0, RadioGroup radioGroup, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 == R.id.rb_aivideochange_open) {
            this$0.is_public = "y";
        } else {
            this$0.is_public = "n";
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initEvents$lambda-6$lambda-5, reason: not valid java name */
    public static final void m5959initEvents$lambda6$lambda5(PostAiChangeFaceVideoFragment this$0, AIPostConfigsBean aIPostConfigsBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getTv_aivideo_changeface_bottomtips().setText(aIPostConfigsBean.ai_tips);
        TextView tv_aivideo_changeface_minnum = this$0.getTv_aivideo_changeface_minnum();
        StringBuilder m586H = C1499a.m586H("(必填，至少");
        m586H.append((Object) aIPostConfigsBean.ai_change_video_min_face_num);
        m586H.append("张)");
        tv_aivideo_changeface_minnum.setText(m586H.toString());
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
        maxSelectNum.selectionData(arrayList).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$selectImage$2
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                MediaSelectAdapter gridImageAdapter;
                boolean z = true;
                C2818e.m3273b("Image", JSON.toJSONString(result));
                if (result != null && !result.isEmpty()) {
                    z = false;
                }
                if (z) {
                    return;
                }
                PostAiChangeFaceVideoFragment.this.mImagePath = result.get(0).getRealPath();
                gridImageAdapter = PostAiChangeFaceVideoFragment.this.getGridImageAdapter();
                gridImageAdapter.replaceData(result);
                TextView btn_submit_aichangeface_video = PostAiChangeFaceVideoFragment.this.getBtn_submit_aichangeface_video();
                AIPostConfigsBean value = PostAiChangeFaceVideoFragment.this.getViewModel().getAIPostConfigsBean().getValue();
                btn_submit_aichangeface_video.setText(Intrinsics.stringPlus(value == null ? null : value.ai_change_video_price, "金币"));
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
        C0949c c0949c = new C0949c(substring, substring2, user_id, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$uploadImages$3
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
        this.jobUploadImages = c0949c.m292c(arrayList4, new Function1<ArrayList<UploadPicResponse.DataBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$uploadImages$6
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
                String str5;
                String str6;
                String str7;
                String str8;
                String str9;
                String str10;
                String str11;
                Intrinsics.checkNotNullParameter(result, "result");
                PostAiChangeFaceVideoFragment postAiChangeFaceVideoFragment = PostAiChangeFaceVideoFragment.this;
                for (UploadPicResponse.DataBean dataBean : result) {
                    StringBuilder sb = new StringBuilder();
                    str11 = postAiChangeFaceVideoFragment.imagesBase;
                    sb.append(str11);
                    sb.append(dataBean.getFile());
                    sb.append(',');
                    postAiChangeFaceVideoFragment.imagesBase = sb.toString();
                }
                PostAiChangeFaceVideoFragment postAiChangeFaceVideoFragment2 = PostAiChangeFaceVideoFragment.this;
                str5 = postAiChangeFaceVideoFragment2.imagesBase;
                str6 = PostAiChangeFaceVideoFragment.this.imagesBase;
                String substring3 = str5.substring(0, str6.length() - 1);
                Intrinsics.checkNotNullExpressionValue(substring3, "this as java.lang.String…ing(startIndex, endIndex)");
                postAiChangeFaceVideoFragment2.imagesBase = substring3;
                AIViewModel viewModel = PostAiChangeFaceVideoFragment.this.getViewModel();
                String obj2 = StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAiChangeFaceVideoFragment.this.getEt_aivideochangeface_info().getText())).toString();
                str7 = PostAiChangeFaceVideoFragment.this.imagesBase;
                str8 = PostAiChangeFaceVideoFragment.this.video_image;
                str9 = PostAiChangeFaceVideoFragment.this.video_value;
                str10 = PostAiChangeFaceVideoFragment.this.is_public;
                final PostAiChangeFaceVideoFragment postAiChangeFaceVideoFragment3 = PostAiChangeFaceVideoFragment.this;
                viewModel.postDoChangeVideo(obj2, str7, str8, str9, str10, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$uploadImages$6.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        PostAiChangeFaceVideoFragment.this.hideLoadingDialog();
                        if (z) {
                            MyBoughtActivity.Companion companion = MyBoughtActivity.INSTANCE;
                            Context requireContext = PostAiChangeFaceVideoFragment.this.requireContext();
                            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                            companion.start(requireContext, 3);
                            FragmentActivity activity = PostAiChangeFaceVideoFragment.this.getActivity();
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
    public final AppCompatEditText getEt_aivideochangeface_info() {
        return (AppCompatEditText) this.et_aivideochangeface_info.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_aivideo_changeface;
    }

    @NotNull
    public final RadioButton getRb_aivideochange_open() {
        return (RadioButton) this.rb_aivideochange_open.getValue();
    }

    @NotNull
    public final RadioGroup getRg_aivideochangeface_open_private() {
        return (RadioGroup) this.rg_aivideochangeface_open_private.getValue();
    }

    @NotNull
    public final RecyclerView getRv_image_base() {
        return (RecyclerView) this.rv_image_base.getValue();
    }

    @NotNull
    public final TextView getTv_aivideo_changeface_bottomtips() {
        return (TextView) this.tv_aivideo_changeface_bottomtips.getValue();
    }

    @NotNull
    public final TextView getTv_aivideo_changeface_minnum() {
        return (TextView) this.tv_aivideo_changeface_minnum.getValue();
    }

    @NotNull
    public final AIViewModel getViewModel() {
        return (AIViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        super.initEvents();
        getViewModel().postAiConfigs();
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
        C2354n.m2374A(getBtn_submit_aichangeface_video(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$initEvents$2
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
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(StringsKt__StringsKt.trim((CharSequence) String.valueOf(PostAiChangeFaceVideoFragment.this.getEt_aivideochangeface_info().getText())).toString(), "")) {
                    C2354n.m2525w0("请输入描述内容");
                    return;
                }
                gridImageAdapter2 = PostAiChangeFaceVideoFragment.this.getGridImageAdapter();
                if (gridImageAdapter2.getData().size() == 1) {
                    C2354n.m2525w0("上传人脸参考照片");
                } else {
                    PostAiChangeFaceVideoFragment.this.uploadImages();
                }
            }
        }, 1);
        getRg_aivideochangeface_open_private().setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: b.a.a.a.t.k.f.k
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup, int i2) {
                PostAiChangeFaceVideoFragment.m5958initEvents$lambda4(PostAiChangeFaceVideoFragment.this, radioGroup, i2);
            }
        });
        AIViewModel viewModel = getViewModel();
        getRb_aivideochange_open().setChecked(true);
        viewModel.getAIPostConfigsBean().observe(this, new Observer() { // from class: b.a.a.a.t.k.f.n
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PostAiChangeFaceVideoFragment.m5959initEvents$lambda6$lambda5(PostAiChangeFaceVideoFragment.this, (AIPostConfigsBean) obj);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        BaseVideoItemFragment newInstance$default = BaseVideoItemFragment.Companion.newInstance$default(BaseVideoItemFragment.INSTANCE, null, 1, null);
        getChildFragmentManager().beginTransaction().replace(R.id.frag_videos, newInstance$default).commit();
        newInstance$default.setCallBack(new Function1<AIPostConfigsBean.AiChangeVideoTemplateBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostAiChangeFaceVideoFragment$initViews$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(AIPostConfigsBean.AiChangeVideoTemplateBean aiChangeVideoTemplateBean) {
                invoke2(aiChangeVideoTemplateBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull AIPostConfigsBean.AiChangeVideoTemplateBean it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PostAiChangeFaceVideoFragment postAiChangeFaceVideoFragment = PostAiChangeFaceVideoFragment.this;
                String str = it.video_value;
                Intrinsics.checkNotNullExpressionValue(str, "it.video_value");
                postAiChangeFaceVideoFragment.video_value = str;
                PostAiChangeFaceVideoFragment postAiChangeFaceVideoFragment2 = PostAiChangeFaceVideoFragment.this;
                String str2 = it.image_value;
                Intrinsics.checkNotNullExpressionValue(str2, "it.image_value");
                postAiChangeFaceVideoFragment2.video_image = str2;
            }
        });
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

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public AIViewModel viewModelInstance() {
        return getViewModel();
    }
}

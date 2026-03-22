package com.jbzd.media.movecartoons.p396ui.post;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.SpannableStringBuilder;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.ForegroundColorSpan;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.UploadPicResponse;
import com.jbzd.media.movecartoons.bean.UploadVideoResponse;
import com.jbzd.media.movecartoons.bean.response.TagSubBean;
import com.jbzd.media.movecartoons.bean.response.UploadBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.UploadingDialog;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.trade.MediaSelectAdapter;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.post.PostInputActivity;
import com.jbzd.media.movecartoons.p396ui.post.PostVideoTagChooseActivity;
import com.jbzd.media.movecartoons.p396ui.post.SelectTagsActivity;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationH;
import com.luck.picture.lib.PictureSelectionModel;
import com.luck.picture.lib.PictureSelector;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.luck.picture.lib.tools.PictureFileUtils;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0875w;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p006a.p007a.p008a.p017r.p022o.C0949c;
import p005b.p006a.p007a.p008a.p017r.p022o.C0950d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p166q.p167i.AbstractC1784c;
import p005b.p143g.p144a.p166q.p168j.InterfaceC1793b;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0082\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0010\u000e\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u001a\n\u0002\u0018\u0002\n\u0002\b!\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0010\u0018\u0000 \u009b\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u009b\u0001B\b¢\u0006\u0005\b\u009a\u0001\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0005J\u001f\u0010\u000b\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\tH\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\r\u0010\u0005J\u000f\u0010\u000e\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u000e\u0010\u0005J\u000f\u0010\u000f\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u000f\u0010\u0005J\u000f\u0010\u0010\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0010\u0010\u0005J\u000f\u0010\u0011\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0011\u0010\u0005J\u0017\u0010\u0014\u001a\u00020\u00032\u0006\u0010\u0013\u001a\u00020\u0012H\u0002¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\u0012H\u0002¢\u0006\u0004\b\u0016\u0010\u0017J\u0017\u0010\u0019\u001a\u00020\u00032\u0006\u0010\u0018\u001a\u00020\u0012H\u0002¢\u0006\u0004\b\u0019\u0010\u0015J\u000f\u0010\u001a\u001a\u00020\tH\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u000f\u0010\u001c\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u001c\u0010\u0005J\u000f\u0010\u001d\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u001d\u0010\u0017J\u000f\u0010\u001e\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u001e\u0010\u0017J\u000f\u0010\u001f\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u001f\u0010\u0005J\r\u0010 \u001a\u00020\u0002¢\u0006\u0004\b \u0010!R9\u0010)\u001a\u001e\u0012\u0004\u0012\u00020\u0012\u0012\u0004\u0012\u00020#0\"j\u000e\u0012\u0004\u0012\u00020\u0012\u0012\u0004\u0012\u00020#`$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010&\u001a\u0004\b'\u0010(R\"\u0010*\u001a\u00020\u00128\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b*\u0010+\u001a\u0004\b,\u0010\u0017\"\u0004\b-\u0010\u0015R\u001f\u00100\u001a\u0004\u0018\u00010\u00128B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010&\u001a\u0004\b/\u0010\u0017R\u0018\u00102\u001a\u0004\u0018\u0001018\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b2\u00103R\u001d\u00108\u001a\u0002048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b5\u0010&\u001a\u0004\b6\u00107R\u001d\u0010=\u001a\u0002098F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b:\u0010&\u001a\u0004\b;\u0010<R\u001d\u0010A\u001a\u00020\u00078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b>\u0010&\u001a\u0004\b?\u0010@R\u001d\u0010F\u001a\u00020B8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bC\u0010&\u001a\u0004\bD\u0010ER\u0018\u0010G\u001a\u0004\u0018\u00010\u00128\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bG\u0010+R6\u0010K\u001a\u0016\u0012\u0004\u0012\u00020I\u0018\u00010Hj\n\u0012\u0004\u0012\u00020I\u0018\u0001`J8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bK\u0010L\u001a\u0004\bM\u0010N\"\u0004\bO\u0010PR\u0018\u0010Q\u001a\u0004\u0018\u0001018\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bQ\u00103R\"\u0010R\u001a\u00020\u00128\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bR\u0010+\u001a\u0004\bS\u0010\u0017\"\u0004\bT\u0010\u0015R\"\u0010U\u001a\u00020\u00128\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bU\u0010+\u001a\u0004\bV\u0010\u0017\"\u0004\bW\u0010\u0015R\u001d\u0010Z\u001a\u0002048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bX\u0010&\u001a\u0004\bY\u00107R\u001d\u0010]\u001a\u0002098F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b[\u0010&\u001a\u0004\b\\\u0010<R\"\u0010^\u001a\u00020\u00128\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b^\u0010+\u001a\u0004\b_\u0010\u0017\"\u0004\b`\u0010\u0015R\u001d\u0010c\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\ba\u0010&\u001a\u0004\bb\u0010!R\u0018\u0010d\u001a\u0004\u0018\u00010\u00128\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bd\u0010+R\u001d\u0010i\u001a\u00020e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bf\u0010&\u001a\u0004\bg\u0010hR\"\u0010j\u001a\u00020\u00128\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bj\u0010+\u001a\u0004\bk\u0010\u0017\"\u0004\bl\u0010\u0015R\u0018\u0010m\u001a\u0004\u0018\u0001018\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bm\u00103R\u001d\u0010p\u001a\u0002098F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bn\u0010&\u001a\u0004\bo\u0010<R\"\u0010q\u001a\u00020\u00128\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bq\u0010+\u001a\u0004\br\u0010\u0017\"\u0004\bs\u0010\u0015R\u001d\u0010v\u001a\u00020e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bt\u0010&\u001a\u0004\bu\u0010hR\u001d\u0010y\u001a\u00020B8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bw\u0010&\u001a\u0004\bx\u0010ER\u0016\u0010z\u001a\u00020\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bz\u0010{R\u001d\u0010~\u001a\u00020\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b|\u0010&\u001a\u0004\b}\u0010\u001bR\u001f\u0010\u0081\u0001\u001a\u00020\u00078B@\u0002X\u0082\u0084\u0002¢\u0006\r\n\u0004\b\u007f\u0010&\u001a\u0005\b\u0080\u0001\u0010@R\u001a\u0010\u0082\u0001\u001a\u0004\u0018\u00010\u00128\u0002@\u0002X\u0082\u000e¢\u0006\u0007\n\u0005\b\u0082\u0001\u0010+R \u0010\u0085\u0001\u001a\u0002048F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0083\u0001\u0010&\u001a\u0005\b\u0084\u0001\u00107R\u001a\u0010\u0086\u0001\u001a\u0004\u0018\u0001018\u0002@\u0002X\u0082\u000e¢\u0006\u0007\n\u0005\b\u0086\u0001\u00103R\"\u0010\u008b\u0001\u001a\u00030\u0087\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u0088\u0001\u0010&\u001a\u0006\b\u0089\u0001\u0010\u008a\u0001R\"\u0010\u0090\u0001\u001a\u00030\u008c\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u008d\u0001\u0010&\u001a\u0006\b\u008e\u0001\u0010\u008f\u0001R:\u0010\u0091\u0001\u001a\u0016\u0012\u0004\u0012\u00020I\u0018\u00010Hj\n\u0012\u0004\u0012\u00020I\u0018\u0001`J8\u0006@\u0006X\u0086\u000e¢\u0006\u0015\n\u0005\b\u0091\u0001\u0010L\u001a\u0005\b\u0092\u0001\u0010N\"\u0005\b\u0093\u0001\u0010PR \u0010\u0096\u0001\u001a\u00020B8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0094\u0001\u0010&\u001a\u0005\b\u0095\u0001\u0010ER \u0010\u0099\u0001\u001a\u00020B8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0097\u0001\u0010&\u001a\u0005\b\u0098\u0001\u0010E¨\u0006\u009c\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/PostInputActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/post/PostViewModel;", "", "selectImage", "()V", "restoreDefaultState", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "adapter", "", "position", "removeItem", "(Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;I)V", "selectVideo", "uploadVideo", "uploadImages", "postSave", "movieAdd", "", PictureConfig.EXTRA_VIDEO_PATH, "generateVideoCoverPath", "(Ljava/lang/String;)V", "getVideoThumbnailDir", "()Ljava/lang/String;", "tags", "showTag", "getLayoutId", "()I", "bindEvent", "getTopBarTitle", "getRightTitle", "clickRight", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/post/PostViewModel;", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "body$delegate", "Lkotlin/Lazy;", "getBody", "()Ljava/util/HashMap;", "body", "uploadVideoBaseUrl", "Ljava/lang/String;", "getUploadVideoBaseUrl", "setUploadVideoBaseUrl", "intoPage$delegate", "getIntoPage", "intoPage", "Lc/a/d1;", "jobUploadVideoCover", "Lc/a/d1;", "Landroidx/appcompat/widget/AppCompatEditText;", "ed_post_money$delegate", "getEd_post_money", "()Landroidx/appcompat/widget/AppCompatEditText;", "ed_post_money", "Landroid/widget/LinearLayout;", "ll_posttopic_name$delegate", "getLl_posttopic_name", "()Landroid/widget/LinearLayout;", "ll_posttopic_name", "videoAdapter$delegate", "getVideoAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "videoAdapter", "Landroid/widget/TextView;", "tv_tags_selected$delegate", "getTv_tags_selected", "()Landroid/widget/TextView;", "tv_tags_selected", "mImagePath", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/TagSubBean;", "Lkotlin/collections/ArrayList;", "tagsAll", "Ljava/util/ArrayList;", "getTagsAll", "()Ljava/util/ArrayList;", "setTagsAll", "(Ljava/util/ArrayList;)V", "saveJob", "uploadVideoToken", "getUploadVideoToken", "setUploadVideoToken", "uploadBaseUrl", "getUploadBaseUrl", "setUploadBaseUrl", "et_aivideochangeface_info$delegate", "getEt_aivideochangeface_info", "et_aivideochangeface_info", "ll_postimage$delegate", "getLl_postimage", "ll_postimage", "uploadImgBaseUrl", "getUploadImgBaseUrl", "setUploadImgBaseUrl", "viewModel$delegate", "getViewModel", "viewModel", "mVideoPath", "Landroidx/recyclerview/widget/RecyclerView;", "rv_image$delegate", "getRv_image", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_image", "uploadToken", "getUploadToken", "setUploadToken", "jobUploadVideo", "ll_postvideo$delegate", "getLl_postvideo", "ll_postvideo", "uploadImgToken", "getUploadImgToken", "setUploadImgToken", "rv_video$delegate", "getRv_video", "rv_video", "tv_media_video_tips$delegate", "getTv_media_video_tips", "tv_media_video_tips", "mChosenMediaType", "I", "postType$delegate", "getPostType", "postType", "gridImageAdapter$delegate", "getGridImageAdapter", "gridImageAdapter", "mVideoCoverPath", "ed_postopic_title$delegate", "getEd_postopic_title", "ed_postopic_title", "jobUploadImages", "Lcom/jbzd/media/movecartoons/ui/dialog/UploadingDialog;", "uploadingDialog$delegate", "getUploadingDialog", "()Lcom/jbzd/media/movecartoons/ui/dialog/UploadingDialog;", "uploadingDialog", "Lcom/jbzd/media/movecartoons/bean/response/UploadBean;", "mUploadBean$delegate", "getMUploadBean", "()Lcom/jbzd/media/movecartoons/bean/response/UploadBean;", "mUploadBean", "curTags", "getCurTags", "setCurTags", "btn_submit_aichangeface_video$delegate", "getBtn_submit_aichangeface_video", "btn_submit_aichangeface_video", "tv_media_title$delegate", "getTv_media_title", "tv_media_title", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostInputActivity extends MyThemeActivity<PostViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String typePost = "";

    @Nullable
    private ArrayList<TagSubBean> curTags;

    @Nullable
    private InterfaceC3053d1 jobUploadImages;

    @Nullable
    private InterfaceC3053d1 jobUploadVideo;

    @Nullable
    private InterfaceC3053d1 jobUploadVideoCover;
    private int mChosenMediaType;

    @Nullable
    private String mImagePath;

    @Nullable
    private String mVideoPath;

    @Nullable
    private InterfaceC3053d1 saveJob;

    @Nullable
    private ArrayList<TagSubBean> tagsAll;

    @Nullable
    private String mVideoCoverPath = "";

    @NotNull
    private String uploadImgBaseUrl = "";

    @NotNull
    private String uploadVideoBaseUrl = "";

    @NotNull
    private String uploadImgToken = "";

    @NotNull
    private String uploadVideoToken = "";

    @NotNull
    private String uploadBaseUrl = "";

    @NotNull
    private String uploadToken = "";

    /* renamed from: body$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy body = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, Object>>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$body$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, Object> invoke() {
            return new HashMap<>();
        }
    });

    /* renamed from: uploadingDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy uploadingDialog = LazyKt__LazyJVMKt.lazy(new Function0<UploadingDialog>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadingDialog$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final UploadingDialog invoke() {
            return UploadingDialog.INSTANCE.newInstance();
        }
    });

    /* renamed from: postType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy postType = LazyKt__LazyJVMKt.lazy(new Function0<Integer>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$postType$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Integer invoke() {
            return Integer.valueOf(invoke2());
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final int invoke2() {
            return PostInputActivity.this.getIntent().getIntExtra("type", 0);
        }
    });

    /* renamed from: intoPage$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy intoPage = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$intoPage$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return PostInputActivity.this.getIntent().getStringExtra("intopage");
        }
    });

    /* renamed from: mUploadBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mUploadBean = LazyKt__LazyJVMKt.lazy(new Function0<UploadBean>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$mUploadBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final UploadBean invoke() {
            UploadBean uploadBean = (UploadBean) PostInputActivity.this.getIntent().getSerializableExtra("uploadbean");
            return uploadBean == null ? new UploadBean() : uploadBean;
        }
    });

    /* renamed from: gridImageAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy gridImageAdapter = LazyKt__LazyJVMKt.lazy(new PostInputActivity$gridImageAdapter$2(this));

    /* renamed from: videoAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy videoAdapter = LazyKt__LazyJVMKt.lazy(new PostInputActivity$videoAdapter$2(this));

    /* renamed from: rv_video$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_video = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$rv_video$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) PostInputActivity.this.findViewById(R.id.rv_video);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: rv_image$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_image = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$rv_image$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) PostInputActivity.this.findViewById(R.id.rv_image);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: tv_tags_selected$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_tags_selected = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$tv_tags_selected$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostInputActivity.this.findViewById(R.id.tv_tags_selected);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_media_video_tips$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_media_video_tips = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$tv_media_video_tips$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostInputActivity.this.findViewById(R.id.tv_media_video_tips);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_media_title$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_media_title = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$tv_media_title$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostInputActivity.this.findViewById(R.id.tv_media_title);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: ll_postimage$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_postimage = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$ll_postimage$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostInputActivity.this.findViewById(R.id.ll_postimage);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_postvideo$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_postvideo = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$ll_postvideo$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostInputActivity.this.findViewById(R.id.ll_postvideo);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: et_aivideochangeface_info$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy et_aivideochangeface_info = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$et_aivideochangeface_info$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatEditText invoke() {
            AppCompatEditText appCompatEditText = (AppCompatEditText) PostInputActivity.this.findViewById(R.id.et_aivideochangeface_info);
            Intrinsics.checkNotNull(appCompatEditText);
            return appCompatEditText;
        }
    });

    /* renamed from: ll_posttopic_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_posttopic_name = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$ll_posttopic_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostInputActivity.this.findViewById(R.id.ll_posttopic_name);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: btn_submit_aichangeface_video$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_submit_aichangeface_video = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$btn_submit_aichangeface_video$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostInputActivity.this.findViewById(R.id.btn_submit_aichangeface_video);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: ed_postopic_title$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ed_postopic_title = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$ed_postopic_title$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatEditText invoke() {
            AppCompatEditText appCompatEditText = (AppCompatEditText) PostInputActivity.this.findViewById(R.id.ed_postopic_title);
            Intrinsics.checkNotNull(appCompatEditText);
            return appCompatEditText;
        }
    });

    /* renamed from: ed_post_money$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ed_post_money = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$ed_post_money$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatEditText invoke() {
            AppCompatEditText appCompatEditText = (AppCompatEditText) PostInputActivity.this.findViewById(R.id.ed_post_money);
            Intrinsics.checkNotNull(appCompatEditText);
            return appCompatEditText;
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(PostViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$special$$inlined$viewModels$default$1
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

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0012\u0010\u0013J-\u0010\n\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006¢\u0006\u0004\b\n\u0010\u000bR\"\u0010\f\u001a\u00020\u00068\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011¨\u0006\u0014"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/PostInputActivity$Companion;", "", "Landroid/content/Context;", "context", "", "type", "", "intopage", "type_post", "", "start", "(Landroid/content/Context;ILjava/lang/String;Ljava/lang/String;)V", "typePost", "Ljava/lang/String;", "getTypePost", "()Ljava/lang/String;", "setTypePost", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getTypePost() {
            return PostInputActivity.typePost;
        }

        public final void setTypePost(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            PostInputActivity.typePost = str;
        }

        public final void start(@NotNull Context context, int type, @NotNull String intopage, @NotNull String type_post) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(intopage, "intopage");
            Intrinsics.checkNotNullParameter(type_post, "type_post");
            setTypePost(type_post);
            context.startActivity(new Intent(context, (Class<?>) PostInputActivity.class).putExtra("type", type).putExtra("intopage", intopage));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5943bindEvent$lambda5$lambda4(List list) {
    }

    private final void generateVideoCoverPath(String videoPath) {
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        Intrinsics.checkNotNull(applicationC2828a);
        ComponentCallbacks2C1553c.m738h(applicationC2828a).mo769b().mo1074D(0.6f).mo763X(videoPath).m755P(new AbstractC1784c<Bitmap>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$generateVideoCoverPath$1
            @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
            public void onLoadCleared(@Nullable Drawable placeholder) {
            }

            @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
            public /* bridge */ /* synthetic */ void onResourceReady(Object obj, InterfaceC1793b interfaceC1793b) {
                onResourceReady((Bitmap) obj, (InterfaceC1793b<? super Bitmap>) interfaceC1793b);
            }

            /* JADX WARN: Multi-variable type inference failed */
            /* JADX WARN: Type inference failed for: r1v0 */
            /* JADX WARN: Type inference failed for: r1v1 */
            /* JADX WARN: Type inference failed for: r1v10 */
            /* JADX WARN: Type inference failed for: r1v11 */
            /* JADX WARN: Type inference failed for: r1v3, types: [java.io.Closeable] */
            /* JADX WARN: Type inference failed for: r1v4 */
            /* JADX WARN: Type inference failed for: r1v6, types: [java.io.Closeable] */
            /* JADX WARN: Type inference failed for: r6v0, types: [android.graphics.Bitmap, java.lang.Object] */
            public void onResourceReady(@NotNull Bitmap resource, @Nullable InterfaceC1793b<? super Bitmap> transition) {
                Throwable th;
                FileOutputStream fileOutputStream;
                IOException e2;
                String videoThumbnailDir;
                Intrinsics.checkNotNullParameter(resource, "resource");
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                ?? r1 = 60;
                resource.compress(Bitmap.CompressFormat.JPEG, 60, byteArrayOutputStream);
                try {
                    try {
                        videoThumbnailDir = PostInputActivity.this.getVideoThumbnailDir();
                        File file = new File(videoThumbnailDir, "thumbnails_" + System.currentTimeMillis() + ".jpg");
                        fileOutputStream = new FileOutputStream(file);
                        try {
                            fileOutputStream.write(byteArrayOutputStream.toByteArray());
                            fileOutputStream.flush();
                            PostInputActivity.this.mVideoCoverPath = file.getAbsolutePath();
                            r1 = fileOutputStream;
                        } catch (IOException e3) {
                            e2 = e3;
                            e2.printStackTrace();
                            r1 = fileOutputStream;
                            PictureFileUtils.close(r1);
                            PictureFileUtils.close(byteArrayOutputStream);
                        }
                    } catch (Throwable th2) {
                        th = th2;
                        PictureFileUtils.close(r1);
                        PictureFileUtils.close(byteArrayOutputStream);
                        throw th;
                    }
                } catch (IOException e4) {
                    fileOutputStream = null;
                    e2 = e4;
                } catch (Throwable th3) {
                    r1 = 0;
                    th = th3;
                    PictureFileUtils.close(r1);
                    PictureFileUtils.close(byteArrayOutputStream);
                    throw th;
                }
                PictureFileUtils.close(r1);
                PictureFileUtils.close(byteArrayOutputStream);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final HashMap<String, Object> getBody() {
        return (HashMap) this.body.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MediaSelectAdapter getGridImageAdapter() {
        return (MediaSelectAdapter) this.gridImageAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getIntoPage() {
        return (String) this.intoPage.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final UploadBean getMUploadBean() {
        return (UploadBean) this.mUploadBean.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int getPostType() {
        return ((Number) this.postType.getValue()).intValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final UploadingDialog getUploadingDialog() {
        return (UploadingDialog) this.uploadingDialog.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MediaSelectAdapter getVideoAdapter() {
        return (MediaSelectAdapter) this.videoAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getVideoThumbnailDir() {
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        File externalFilesDir = applicationC2828a.getExternalFilesDir("");
        Intrinsics.checkNotNull(externalFilesDir);
        File file = new File(externalFilesDir.getAbsolutePath(), "Thumbnails");
        if (!file.exists()) {
            file.mkdirs();
        }
        return Intrinsics.stringPlus(file.getAbsolutePath(), File.separator);
    }

    private final PostViewModel getViewModel() {
        return (PostViewModel) this.viewModel.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void movieAdd() {
        getMUploadBean().preview = "1";
        cancelJob(this.saveJob);
        getBody().put("name", StringsKt__StringsKt.trim((CharSequence) String.valueOf(getEd_postopic_title().getText())).toString());
        if (Intrinsics.areEqual(StringsKt__StringsKt.trim((CharSequence) String.valueOf(getEd_post_money().getText())).toString(), "")) {
            getBody().put("money", "0");
        } else {
            getBody().put("money", Integer.valueOf(Integer.parseInt(String.valueOf(getEd_post_money().getText()))));
        }
        HashMap<String, Object> body = getBody();
        String str = getMUploadBean().img;
        Intrinsics.checkNotNullExpressionValue(str, "mUploadBean.img");
        body.put("img", str);
        HashMap<String, Object> body2 = getBody();
        String str2 = getMUploadBean().preview_m3u8_url;
        Intrinsics.checkNotNullExpressionValue(str2, "mUploadBean.preview_m3u8_url");
        body2.put("preview_m3u8_url", str2);
        HashMap<String, Object> body3 = getBody();
        String str3 = getMUploadBean().m3u8_url;
        Intrinsics.checkNotNullExpressionValue(str3, "mUploadBean.m3u8_url");
        body3.put("m3u8_url", str3);
        HashMap<String, Object> body4 = getBody();
        String str4 = getMUploadBean().tag_id;
        Intrinsics.checkNotNullExpressionValue(str4, "mUploadBean.tag_id");
        body4.put("tag_ids", str4);
        HashMap<String, Object> body5 = getBody();
        String str5 = getMUploadBean().duration;
        Intrinsics.checkNotNullExpressionValue(str5, "mUploadBean.duration");
        body5.put("duration", str5);
        HashMap<String, Object> body6 = getBody();
        String str6 = getMUploadBean().quality;
        Intrinsics.checkNotNullExpressionValue(str6, "mUploadBean.quality");
        body6.put("quality", str6);
        this.saveJob = C0917a.m221e(C0917a.f372a, "movie/add", String.class, getBody(), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$movieAdd$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str7) {
                invoke2(str7);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str7) {
                PostInputActivity.this.hideLoadingDialog();
                PostInputActivity.this.finish();
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$movieAdd$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PostInputActivity.this.hideLoadingDialog();
            }
        }, false, false, null, false, 480);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void postSave() {
        cancelJob(this.saveJob);
        getBody().put(VideoListActivity.KEY_TITLE, StringsKt__StringsKt.trim((CharSequence) String.valueOf(getEd_postopic_title().getText())).toString());
        HashMap<String, Object> body = getBody();
        String str = getMUploadBean().tag_id;
        Intrinsics.checkNotNullExpressionValue(str, "mUploadBean.tag_id");
        body.put("categories", str);
        getBody().put("content", StringsKt__StringsKt.trim((CharSequence) String.valueOf(getEt_aivideochangeface_info().getText())).toString());
        HashMap<String, Object> body2 = getBody();
        String str2 = getMUploadBean().img;
        Intrinsics.checkNotNullExpressionValue(str2, "mUploadBean.img");
        body2.put("images", str2);
        if (Intrinsics.areEqual(StringsKt__StringsKt.trim((CharSequence) String.valueOf(getEd_post_money().getText())).toString(), "")) {
            getBody().put("money", "0");
        } else {
            getBody().put("money", Integer.valueOf(Integer.parseInt(String.valueOf(getEd_post_money().getText()))));
        }
        this.saveJob = C0917a.m221e(C0917a.f372a, "post/save", String.class, getBody(), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$postSave$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str3) {
                invoke2(str3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str3) {
                String intoPage;
                C2354n.m2409L1("发布成功");
                PostInputActivity.this.hideLoadingDialog();
                PostInputActivity.Companion companion = PostInputActivity.INSTANCE;
                if (!Intrinsics.areEqual(companion.getTypePost(), "homepage")) {
                    intoPage = PostInputActivity.this.getIntoPage();
                    if (!Intrinsics.areEqual(intoPage, "homepage")) {
                        if (Intrinsics.areEqual(companion.getTypePost(), "mypost")) {
                            MyApp myApp = MyApp.f9891f;
                            Intrinsics.checkNotNullParameter("1", "<set-?>");
                            MyApp.f9893h = "1";
                            PostInputActivity.this.finish();
                            return;
                        }
                        return;
                    }
                }
                MyPostListActivity.Companion.start(PostInputActivity.this, 1);
                PostInputActivity.this.finish();
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$postSave$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PostInputActivity.this.hideLoadingDialog();
            }
        }, false, false, null, false, 480);
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
        getRv_video().setVisibility(0);
        getRv_image().setVisibility(0);
        this.mVideoPath = null;
        this.mImagePath = null;
        this.mVideoCoverPath = null;
        getVideoAdapter().setupMedia(MediaSelectAdapter.MediaType.Video.INSTANCE);
        getGridImageAdapter().setupMedia(MediaSelectAdapter.MediaType.Image.INSTANCE);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void selectImage() {
        this.mChosenMediaType = this.mChosenMediaType != 2 ? 1 : 2;
        getGridImageAdapter().setupMedia(this.mChosenMediaType == 2 ? MediaSelectAdapter.MediaType.Cover.INSTANCE : MediaSelectAdapter.MediaType.Image.INSTANCE);
        PictureSelectionModel maxSelectNum = PictureSelector.create(this).openGallery(PictureMimeType.ofImage()).imageEngine(C0875w.m204a()).maxSelectNum((Intrinsics.areEqual(typePost, "homepage") || Intrinsics.areEqual(typePost, "mypost") || Intrinsics.areEqual(typePost, "post")) ? 9 : 1);
        List<LocalMedia> data = getGridImageAdapter().getData();
        ArrayList arrayList = new ArrayList();
        for (Object obj : data) {
            String fileName = ((LocalMedia) obj).getFileName();
            if (!(fileName == null || fileName.length() == 0)) {
                arrayList.add(obj);
            }
        }
        maxSelectNum.selectionData(arrayList).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$selectImage$2
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                MediaSelectAdapter gridImageAdapter;
                if (result == null || result.isEmpty()) {
                    return;
                }
                PostInputActivity postInputActivity = PostInputActivity.this;
                int i2 = Build.VERSION.SDK_INT;
                C2818e.m3272a(Intrinsics.stringPlus("Build.VERSION.SDK_INT:", Integer.valueOf(i2)), new Object[0]);
                postInputActivity.mImagePath = i2 <= 28 ? result.get(0).getPath() : result.get(0).getRealPath();
                gridImageAdapter = PostInputActivity.this.getGridImageAdapter();
                gridImageAdapter.replaceData(result);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void selectVideo() {
        PictureSelectionModel maxSelectNum = PictureSelector.create(this).openGallery(PictureMimeType.ofVideo()).imageEngine(C0875w.m204a()).selectionMode(2).maxSelectNum(3);
        List<LocalMedia> data = getVideoAdapter().getData();
        ArrayList arrayList = new ArrayList();
        for (Object obj : data) {
            String fileName = ((LocalMedia) obj).getFileName();
            if (!(fileName == null || fileName.length() == 0)) {
                arrayList.add(obj);
            }
        }
        maxSelectNum.selectionData(arrayList).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$selectVideo$2
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                MediaSelectAdapter videoAdapter;
                MediaSelectAdapter gridImageAdapter;
                if (result == null || result.isEmpty()) {
                    return;
                }
                int i2 = Build.VERSION.SDK_INT;
                C2818e.m3272a(Intrinsics.stringPlus("Build.VERSION.SDK_INT:", Integer.valueOf(i2)), new Object[0]);
                PostInputActivity.this.mVideoPath = i2 <= 28 ? result.get(0).getPath() : result.get(0).getRealPath();
                PostInputActivity.this.mChosenMediaType = 2;
                videoAdapter = PostInputActivity.this.getVideoAdapter();
                videoAdapter.replaceData(result);
                gridImageAdapter = PostInputActivity.this.getGridImageAdapter();
                gridImageAdapter.setupMedia(MediaSelectAdapter.MediaType.Cover.INSTANCE);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showTag(String tags) {
        if (tags.length() == 0) {
            return;
        }
        if (StringsKt__StringsJVMKt.startsWith$default(tags, "#", false, 2, null)) {
            getTv_tags_selected().setText(tags);
        } else {
            getTv_tags_selected().setText(Intrinsics.stringPlus("#", tags));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void uploadImages() {
        showLoadingDialog("正在提交...", true);
        String str = this.mVideoPath;
        if (str != null && this.mImagePath != null) {
            Intrinsics.checkNotNull(str);
            generateVideoCoverPath(str);
            new Timer().schedule(new TimerTask() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadImages$$inlined$schedule$1
                @Override // java.util.TimerTask, java.lang.Runnable
                public void run() {
                    InterfaceC3053d1 interfaceC3053d1;
                    MediaSelectAdapter gridImageAdapter;
                    String str2;
                    PostInputActivity postInputActivity = PostInputActivity.this;
                    interfaceC3053d1 = postInputActivity.jobUploadVideoCover;
                    postInputActivity.cancelJob(interfaceC3053d1);
                    if (Intrinsics.areEqual(PostInputActivity.typePost, "myvideo")) {
                        PostInputActivity postInputActivity2 = PostInputActivity.this;
                        String uploadImgBaseUrl = postInputActivity2.getUploadImgBaseUrl();
                        String uploadImgToken = PostInputActivity.this.getUploadImgToken();
                        MyApp myApp = MyApp.f9891f;
                        String user_id = MyApp.f9892g.user_id;
                        Intrinsics.checkNotNullExpressionValue(user_id, "user_id");
                        final PostInputActivity postInputActivity3 = PostInputActivity.this;
                        C0949c c0949c = new C0949c(uploadImgBaseUrl, uploadImgToken, user_id, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadImages$1$1
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(String str3) {
                                invoke2(str3);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@Nullable String str3) {
                                PostInputActivity.this.hideLoadingDialog();
                                C2354n.m2379B1(str3);
                            }
                        }, null, "1", 16);
                        str2 = PostInputActivity.this.mImagePath;
                        Intrinsics.checkNotNull(str2);
                        List<String> listOf = CollectionsKt__CollectionsJVMKt.listOf(str2);
                        final PostInputActivity postInputActivity4 = PostInputActivity.this;
                        postInputActivity2.jobUploadVideoCover = c0949c.m292c(listOf, new Function1<ArrayList<UploadPicResponse.DataBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadImages$1$2
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(ArrayList<UploadPicResponse.DataBean> arrayList) {
                                invoke2(arrayList);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull ArrayList<UploadPicResponse.DataBean> result) {
                                UploadBean mUploadBean;
                                Intrinsics.checkNotNullParameter(result, "result");
                                PostInputActivity postInputActivity5 = PostInputActivity.this;
                                for (UploadPicResponse.DataBean dataBean : result) {
                                    mUploadBean = postInputActivity5.getMUploadBean();
                                    mUploadBean.img = dataBean.getFile();
                                }
                                PostInputActivity.this.uploadVideo();
                            }
                        });
                        return;
                    }
                    PostInputActivity postInputActivity5 = PostInputActivity.this;
                    String uploadImgBaseUrl2 = postInputActivity5.getUploadImgBaseUrl();
                    String uploadImgToken2 = PostInputActivity.this.getUploadImgToken();
                    MyApp myApp2 = MyApp.f9891f;
                    String str3 = MyApp.f9892g.user_id;
                    Intrinsics.checkNotNullExpressionValue(str3, "MyApp.userInfo.user_id");
                    final PostInputActivity postInputActivity6 = PostInputActivity.this;
                    C0949c c0949c2 = new C0949c(uploadImgBaseUrl2, uploadImgToken2, str3, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadImages$1$3
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(String str4) {
                            invoke2(str4);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@Nullable String str4) {
                            PostInputActivity.this.hideLoadingDialog();
                            C2354n.m2379B1(str4);
                        }
                    }, null, null, 48);
                    gridImageAdapter = PostInputActivity.this.getGridImageAdapter();
                    List<LocalMedia> data = gridImageAdapter.getData();
                    ArrayList arrayList = new ArrayList();
                    for (Object obj : data) {
                        String realPath = ((LocalMedia) obj).getRealPath();
                        if (!(realPath == null || realPath.length() == 0)) {
                            arrayList.add(obj);
                        }
                    }
                    ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, 10));
                    Iterator it = arrayList.iterator();
                    while (it.hasNext()) {
                        arrayList2.add(((LocalMedia) it.next()).getRealPath());
                    }
                    final PostInputActivity postInputActivity7 = PostInputActivity.this;
                    postInputActivity5.jobUploadVideoCover = c0949c2.m292c(arrayList2, new Function1<ArrayList<UploadPicResponse.DataBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadImages$1$6
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(ArrayList<UploadPicResponse.DataBean> arrayList3) {
                            invoke2(arrayList3);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@NotNull ArrayList<UploadPicResponse.DataBean> result) {
                            UploadBean mUploadBean;
                            UploadBean mUploadBean2;
                            UploadBean mUploadBean3;
                            int postType;
                            int postType2;
                            UploadBean mUploadBean4;
                            Intrinsics.checkNotNullParameter(result, "result");
                            PostInputActivity postInputActivity8 = PostInputActivity.this;
                            for (UploadPicResponse.DataBean dataBean : result) {
                                mUploadBean4 = postInputActivity8.getMUploadBean();
                                mUploadBean4.img += dataBean.getFile() + ',';
                            }
                            mUploadBean = PostInputActivity.this.getMUploadBean();
                            mUploadBean2 = PostInputActivity.this.getMUploadBean();
                            String str4 = mUploadBean2.img;
                            Intrinsics.checkNotNullExpressionValue(str4, "mUploadBean.img");
                            mUploadBean3 = PostInputActivity.this.getMUploadBean();
                            String substring = str4.substring(0, mUploadBean3.img.length() - 1);
                            Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
                            mUploadBean.img = substring;
                            postType = PostInputActivity.this.getPostType();
                            if (postType != 2) {
                                postType2 = PostInputActivity.this.getPostType();
                                if (postType2 != 3) {
                                    return;
                                }
                            }
                            PostInputActivity.this.uploadVideo();
                        }
                    });
                }
            }, 1000L);
            return;
        }
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
        String str2 = this.uploadImgBaseUrl;
        String str3 = this.uploadImgToken;
        MyApp myApp = MyApp.f9891f;
        String user_id = MyApp.f9892g.user_id;
        Intrinsics.checkNotNullExpressionValue(user_id, "user_id");
        C0949c c0949c = new C0949c(str2, str3, user_id, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadImages$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str4) {
                invoke2(str4);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str4) {
                PostInputActivity.this.hideLoadingDialog();
                C2354n.m2379B1(str4);
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
        this.jobUploadImages = c0949c.m292c(arrayList4, new Function1<ArrayList<UploadPicResponse.DataBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadImages$7
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
                UploadBean mUploadBean;
                UploadBean mUploadBean2;
                UploadBean mUploadBean3;
                UploadBean mUploadBean4;
                Intrinsics.checkNotNullParameter(result, "result");
                PostInputActivity postInputActivity = PostInputActivity.this;
                for (UploadPicResponse.DataBean dataBean : result) {
                    mUploadBean4 = postInputActivity.getMUploadBean();
                    mUploadBean4.img += dataBean.getFile() + ',';
                }
                mUploadBean = PostInputActivity.this.getMUploadBean();
                mUploadBean2 = PostInputActivity.this.getMUploadBean();
                String str4 = mUploadBean2.img;
                Intrinsics.checkNotNullExpressionValue(str4, "mUploadBean.img");
                mUploadBean3 = PostInputActivity.this.getMUploadBean();
                String substring = str4.substring(0, mUploadBean3.img.length() - 1);
                Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
                mUploadBean.img = substring;
                PostInputActivity.this.postSave();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void uploadVideo() {
        hideLoadingDialog();
        getUploadingDialog().show(getSupportFragmentManager(), "uploadingDialog");
        String str = this.uploadVideoBaseUrl;
        String str2 = this.mVideoPath;
        Intrinsics.checkNotNull(str2);
        C0950d c0950d = new C0950d(str, str2, this.uploadVideoToken, new Function1<UploadVideoResponse.DataBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadVideo$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(UploadVideoResponse.DataBean dataBean) {
                invoke2(dataBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull UploadVideoResponse.DataBean it) {
                String intoPage;
                HashMap body;
                UploadBean mUploadBean;
                UploadBean mUploadBean2;
                UploadBean mUploadBean3;
                UploadBean mUploadBean4;
                Intrinsics.checkNotNullParameter(it, "it");
                intoPage = PostInputActivity.this.getIntoPage();
                if (!Intrinsics.areEqual(intoPage, "video")) {
                    body = PostInputActivity.this.getBody();
                    String file_m3u8 = it.getFile_m3u8();
                    Intrinsics.checkNotNullExpressionValue(file_m3u8, "it.file_m3u8");
                    body.put("files", file_m3u8);
                    PostInputActivity.this.postSave();
                    return;
                }
                mUploadBean = PostInputActivity.this.getMUploadBean();
                mUploadBean.duration = it.getFile_duration();
                mUploadBean2 = PostInputActivity.this.getMUploadBean();
                mUploadBean2.preview_m3u8_url = it.getFile_preview_m3u8();
                mUploadBean3 = PostInputActivity.this.getMUploadBean();
                mUploadBean3.m3u8_url = it.getFile_m3u8();
                mUploadBean4 = PostInputActivity.this.getMUploadBean();
                mUploadBean4.quality = it.getFile_quality();
                PostInputActivity.this.movieAdd();
            }
        }, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadVideo$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str3) {
                invoke2(str3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str3) {
                UploadingDialog uploadingDialog;
                uploadingDialog = PostInputActivity.this.getUploadingDialog();
                uploadingDialog.dismiss();
                C2354n.m2379B1(str3);
            }
        });
        c0950d.setOnProgressListener(new C0950d.a() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$uploadVideo$3$1
            @Override // p005b.p006a.p007a.p008a.p017r.p022o.C0950d.a
            public void onProgress(int progress, @NotNull String id) {
                UploadingDialog uploadingDialog;
                Intrinsics.checkNotNullParameter(id, "id");
                uploadingDialog = PostInputActivity.this.getUploadingDialog();
                uploadingDialog.setProgress(progress);
            }

            @Override // p005b.p006a.p007a.p008a.p017r.p022o.C0950d.a
            public void onTotal(int total) {
                UploadingDialog uploadingDialog;
                uploadingDialog = PostInputActivity.this.getUploadingDialog();
                uploadingDialog.setMax(total);
            }
        });
        this.jobUploadVideo = c0950d.m297e();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        MyApp myApp = MyApp.f9891f;
        String str = MyApp.m4185f().upload_image_url;
        Intrinsics.checkNotNullExpressionValue(str, "MyApp.systemBean.upload_image_url");
        String str2 = MyApp.m4185f().upload_image_url;
        Intrinsics.checkNotNullExpressionValue(str2, "MyApp.systemBean.upload_image_url");
        String substring = str.substring(0, StringsKt__StringsKt.lastIndexOf$default((CharSequence) str2, "/", 0, false, 6, (Object) null) + 1);
        Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
        this.uploadImgBaseUrl = substring;
        String str3 = MyApp.m4185f().upload_image_url;
        Intrinsics.checkNotNullExpressionValue(str3, "MyApp.systemBean.upload_image_url");
        String str4 = MyApp.m4185f().upload_image_url;
        Intrinsics.checkNotNullExpressionValue(str4, "MyApp.systemBean.upload_image_url");
        String substring2 = str3.substring(StringsKt__StringsKt.indexOf$default((CharSequence) str4, "key=", 0, false, 6, (Object) null) + 4);
        Intrinsics.checkNotNullExpressionValue(substring2, "this as java.lang.String).substring(startIndex)");
        this.uploadImgToken = substring2;
        String str5 = MyApp.m4185f().upload_file_url;
        Intrinsics.checkNotNullExpressionValue(str5, "MyApp.systemBean.upload_file_url");
        String str6 = MyApp.m4185f().upload_file_url;
        Intrinsics.checkNotNullExpressionValue(str6, "MyApp.systemBean.upload_file_url");
        String substring3 = str5.substring(0, StringsKt__StringsKt.lastIndexOf$default((CharSequence) str6, "/", 0, false, 6, (Object) null) + 1);
        Intrinsics.checkNotNullExpressionValue(substring3, "this as java.lang.String…ing(startIndex, endIndex)");
        this.uploadVideoBaseUrl = substring3;
        String str7 = MyApp.m4185f().upload_file_url;
        Intrinsics.checkNotNullExpressionValue(str7, "MyApp.systemBean.upload_file_url");
        String str8 = MyApp.m4185f().upload_file_url;
        Intrinsics.checkNotNullExpressionValue(str8, "MyApp.systemBean.upload_file_url");
        String substring4 = str7.substring(StringsKt__StringsKt.indexOf$default((CharSequence) str8, "key=", 0, false, 6, (Object) null) + 4);
        Intrinsics.checkNotNullExpressionValue(substring4, "this as java.lang.String).substring(startIndex)");
        this.uploadVideoToken = substring4;
        if (!Intrinsics.areEqual(getIntoPage(), "")) {
            if (Intrinsics.areEqual(getIntoPage(), "video")) {
                getTv_tags_selected().setText("选择视频标签");
            } else {
                getTv_tags_selected().setText("选择话题");
            }
        }
        TextView tv_media_video_tips = getTv_media_video_tips();
        StringBuilder m586H = C1499a.m586H("上传视频 最大");
        String str9 = MyApp.m4185f().upload_file_max_length;
        Intrinsics.checkNotNullExpressionValue(str9, "MyApp.systemBean.upload_file_max_length");
        m586H.append((Integer.parseInt(str9) / 1024) / 1024);
        m586H.append("M以内");
        tv_media_video_tips.setText(m586H.toString());
        if (Intrinsics.areEqual(typePost, "homepage") || Intrinsics.areEqual(typePost, "mypost")) {
            StringBuilder m586H2 = C1499a.m586H("[默认第一张为视频封面]上传图片 最多上传9张，最大每张");
            String str10 = MyApp.m4185f().upload_image_max_length;
            Intrinsics.checkNotNullExpressionValue(str10, "MyApp.systemBean.upload_image_max_length");
            m586H2.append((Integer.parseInt(str10) / 1024) / 1024);
            m586H2.append("M以内");
            String sb = m586H2.toString();
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(sb);
            ForegroundColorSpan foregroundColorSpan = new ForegroundColorSpan(Color.parseColor("#ff0000"));
            spannableStringBuilder.setSpan(new AbsoluteSizeSpan(40), 0, 16, 33);
            spannableStringBuilder.setSpan(new AbsoluteSizeSpan(35), 17, sb.length(), 33);
            spannableStringBuilder.setSpan(foregroundColorSpan, 0, 12, 33);
            getTv_media_title().setText(spannableStringBuilder);
        } else {
            StringBuilder m586H3 = C1499a.m586H("最多上传1张，最大");
            String str11 = MyApp.m4185f().upload_image_max_length;
            Intrinsics.checkNotNullExpressionValue(str11, "MyApp.systemBean.upload_image_max_length");
            m586H3.append((Integer.parseInt(str11) / 1024) / 1024);
            m586H3.append("M以内");
            getTv_media_title().setText(m586H3.toString());
        }
        if (getPostType() == 1) {
            getLl_postimage().setVisibility(0);
            getLl_postvideo().setVisibility(8);
            getEt_aivideochangeface_info().setVisibility(8);
        } else if (getPostType() == 2) {
            getLl_postimage().setVisibility(0);
            getLl_postvideo().setVisibility(0);
            getEt_aivideochangeface_info().setVisibility(0);
        } else if (getPostType() == 3) {
            getLl_postimage().setVisibility(0);
            getLl_postvideo().setVisibility(0);
            getEt_aivideochangeface_info().setVisibility(0);
        }
        if (Intrinsics.areEqual(getIntoPage(), "video")) {
            getEt_aivideochangeface_info().setVisibility(8);
        }
        getViewModel().postCategories("normal");
        getViewModel().getTagSubBean().observe(this, new Observer() { // from class: b.a.a.a.t.k.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PostInputActivity.m5943bindEvent$lambda5$lambda4((List) obj);
            }
        });
        C2354n.m2374A(getLl_posttopic_name(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$bindEvent$2$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                String intoPage;
                Intrinsics.checkNotNullParameter(it, "it");
                intoPage = PostInputActivity.this.getIntoPage();
                if (Intrinsics.areEqual(intoPage, "video")) {
                    PostVideoTagChooseActivity.Companion companion = PostVideoTagChooseActivity.Companion;
                    final PostInputActivity postInputActivity = PostInputActivity.this;
                    companion.start(postInputActivity, new Function1<ArrayList<TagSubBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$bindEvent$2$2.1
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(ArrayList<TagSubBean> arrayList) {
                            invoke2(arrayList);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@NotNull ArrayList<TagSubBean> it2) {
                            UploadBean mUploadBean;
                            UploadBean mUploadBean2;
                            Intrinsics.checkNotNullParameter(it2, "it");
                            PostInputActivity.this.setCurTags(it2);
                            String joinToString$default = CollectionsKt___CollectionsKt.joinToString$default(it2, "  #", null, null, 0, null, new Function1<TagSubBean, CharSequence>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$bindEvent$2$2$1$tag_names$1
                                @Override // kotlin.jvm.functions.Function1
                                @NotNull
                                public final CharSequence invoke(@NotNull TagSubBean item) {
                                    Intrinsics.checkNotNullParameter(item, "item");
                                    String name = item.getName();
                                    Intrinsics.checkNotNullExpressionValue(name, "item.name");
                                    return name;
                                }
                            }, 30, null);
                            String joinToString$default2 = CollectionsKt___CollectionsKt.joinToString$default(it2, ChineseToPinyinResource.Field.COMMA, null, null, 0, null, new Function1<TagSubBean, CharSequence>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$bindEvent$2$2$1$tag_ids$1
                                @Override // kotlin.jvm.functions.Function1
                                @NotNull
                                public final CharSequence invoke(@NotNull TagSubBean item) {
                                    Intrinsics.checkNotNullParameter(item, "item");
                                    String id = item.getId();
                                    Intrinsics.checkNotNullExpressionValue(id, "item.id");
                                    return id;
                                }
                            }, 30, null);
                            mUploadBean = PostInputActivity.this.getMUploadBean();
                            mUploadBean.tag_id = joinToString$default2;
                            mUploadBean2 = PostInputActivity.this.getMUploadBean();
                            mUploadBean2.tag_names = joinToString$default;
                            PostInputActivity.this.showTag(joinToString$default);
                        }
                    }, PostInputActivity.this.getCurTags(), PostInputActivity.this.getTagsAll());
                } else {
                    SelectTagsActivity.Companion companion2 = SelectTagsActivity.Companion;
                    final PostInputActivity postInputActivity2 = PostInputActivity.this;
                    companion2.start(postInputActivity2, new Function1<ArrayList<TagSubBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$bindEvent$2$2.2
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(ArrayList<TagSubBean> arrayList) {
                            invoke2(arrayList);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@NotNull ArrayList<TagSubBean> it2) {
                            UploadBean mUploadBean;
                            UploadBean mUploadBean2;
                            Intrinsics.checkNotNullParameter(it2, "it");
                            PostInputActivity.this.setCurTags(it2);
                            String joinToString$default = CollectionsKt___CollectionsKt.joinToString$default(it2, "  #", null, null, 0, null, new Function1<TagSubBean, CharSequence>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$bindEvent$2$2$2$tag_names$1
                                @Override // kotlin.jvm.functions.Function1
                                @NotNull
                                public final CharSequence invoke(@NotNull TagSubBean item) {
                                    Intrinsics.checkNotNullParameter(item, "item");
                                    String name = item.getName();
                                    Intrinsics.checkNotNullExpressionValue(name, "item.name");
                                    return name;
                                }
                            }, 30, null);
                            String joinToString$default2 = CollectionsKt___CollectionsKt.joinToString$default(it2, ChineseToPinyinResource.Field.COMMA, null, null, 0, null, new Function1<TagSubBean, CharSequence>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$bindEvent$2$2$2$tag_ids$1
                                @Override // kotlin.jvm.functions.Function1
                                @NotNull
                                public final CharSequence invoke(@NotNull TagSubBean item) {
                                    Intrinsics.checkNotNullParameter(item, "item");
                                    String id = item.getId();
                                    Intrinsics.checkNotNullExpressionValue(id, "item.id");
                                    return id;
                                }
                            }, 30, null);
                            mUploadBean = PostInputActivity.this.getMUploadBean();
                            mUploadBean.tag_id = joinToString$default2;
                            mUploadBean2 = PostInputActivity.this.getMUploadBean();
                            mUploadBean2.tag_names = joinToString$default;
                            PostInputActivity.this.showTag(joinToString$default);
                        }
                    }, PostInputActivity.this.getCurTags(), PostInputActivity.this.getTagsAll());
                }
            }
        }, 1);
        C2354n.m2374A(getBtn_submit_aichangeface_video(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostInputActivity$bindEvent$2$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* JADX WARN: Code restructure failed: missing block: B:27:0x0094, code lost:
            
                if (kotlin.jvm.internal.Intrinsics.areEqual(r4, "video") != false) goto L33;
             */
            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final void invoke2(@org.jetbrains.annotations.NotNull android.widget.TextView r4) {
                /*
                    r3 = this;
                    java.lang.String r0 = "it"
                    kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    com.jbzd.media.movecartoons.bean.response.UploadBean r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.access$getMUploadBean(r4)
                    java.lang.String r4 = r4.tag_names
                    r0 = 0
                    r1 = 1
                    if (r4 == 0) goto L1a
                    int r4 = r4.length()
                    if (r4 != 0) goto L18
                    goto L1a
                L18:
                    r4 = 0
                    goto L1b
                L1a:
                    r4 = 1
                L1b:
                    if (r4 == 0) goto L2d
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    android.content.Context r4 = r4.getApplicationContext()
                    java.lang.String r0 = "至少选择一个版块"
                    android.widget.Toast r4 = p426f.p427a.p428a.C4325a.m4905h(r4, r0, r1)
                    r4.show()
                    return
                L2d:
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    androidx.appcompat.widget.AppCompatEditText r4 = r4.getEd_postopic_title()
                    android.text.Editable r4 = r4.getText()
                    java.lang.String r4 = java.lang.String.valueOf(r4)
                    int r4 = r4.length()
                    if (r4 != 0) goto L43
                    r4 = 1
                    goto L44
                L43:
                    r4 = 0
                L44:
                    if (r4 == 0) goto L56
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    android.content.Context r4 = r4.getApplicationContext()
                    java.lang.String r0 = "请填写标题"
                    android.widget.Toast r4 = p426f.p427a.p428a.C4325a.m4905h(r4, r0, r1)
                    r4.show()
                    return
                L56:
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    java.lang.String r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.access$getMImagePath$p(r4)
                    if (r4 == 0) goto L67
                    int r4 = r4.length()
                    if (r4 != 0) goto L65
                    goto L67
                L65:
                    r4 = 0
                    goto L68
                L67:
                    r4 = 1
                L68:
                    if (r4 == 0) goto L7a
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    android.content.Context r4 = r4.getApplicationContext()
                    java.lang.String r0 = "请选择图片"
                    android.widget.Toast r4 = p426f.p427a.p428a.C4325a.m4905h(r4, r0, r1)
                    r4.show()
                    return
                L7a:
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    java.lang.String r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.access$getIntoPage(r4)
                    java.lang.String r2 = "post"
                    boolean r4 = kotlin.jvm.internal.Intrinsics.areEqual(r4, r2)
                    if (r4 != 0) goto L96
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    java.lang.String r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.access$getIntoPage(r4)
                    java.lang.String r2 = "video"
                    boolean r4 = kotlin.jvm.internal.Intrinsics.areEqual(r4, r2)
                    if (r4 == 0) goto Lb7
                L96:
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    java.lang.String r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.access$getMVideoPath$p(r4)
                    if (r4 == 0) goto La4
                    int r4 = r4.length()
                    if (r4 != 0) goto La5
                La4:
                    r0 = 1
                La5:
                    if (r0 == 0) goto Lb7
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    android.content.Context r4 = r4.getApplicationContext()
                    java.lang.String r0 = "请选择视频"
                    android.widget.Toast r4 = p426f.p427a.p428a.C4325a.m4905h(r4, r0, r1)
                    r4.show()
                    return
                Lb7:
                    com.jbzd.media.movecartoons.ui.post.PostInputActivity r4 = com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.this
                    com.jbzd.media.movecartoons.p396ui.post.PostInputActivity.access$uploadImages(r4)
                    return
                */
                throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.post.PostInputActivity$bindEvent$2$3.invoke2(android.widget.TextView):void");
            }
        }, 1);
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
            C1499a.m604Z(c4053a, rv_image);
        }
        MediaSelectAdapter gridImageAdapter = getGridImageAdapter();
        gridImageAdapter.addData((MediaSelectAdapter) new LocalMedia());
        Unit unit = Unit.INSTANCE;
        rv_image.setAdapter(gridImageAdapter);
        RecyclerView rv_video = getRv_video();
        ApplicationC2828a applicationC2828a5 = C2827a.f7670a;
        if (applicationC2828a5 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        rv_video.setLayoutManager(new LinearLayoutManager(applicationC2828a5, 0, false));
        if (rv_video.getItemDecorationCount() == 0) {
            ApplicationC2828a applicationC2828a6 = C2827a.f7670a;
            if (applicationC2828a6 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            int m2425R = C2354n.m2425R(applicationC2828a6, 8.0f);
            ApplicationC2828a applicationC2828a7 = C2827a.f7670a;
            if (applicationC2828a7 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            rv_video.addItemDecoration(new ItemDecorationH(m2425R, C2354n.m2425R(applicationC2828a7, 0.0f)));
        }
        MediaSelectAdapter videoAdapter = getVideoAdapter();
        videoAdapter.addData((MediaSelectAdapter) new LocalMedia());
        rv_video.setAdapter(videoAdapter);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void clickRight() {
    }

    @NotNull
    public final TextView getBtn_submit_aichangeface_video() {
        return (TextView) this.btn_submit_aichangeface_video.getValue();
    }

    @Nullable
    public final ArrayList<TagSubBean> getCurTags() {
        return this.curTags;
    }

    @NotNull
    public final AppCompatEditText getEd_post_money() {
        return (AppCompatEditText) this.ed_post_money.getValue();
    }

    @NotNull
    public final AppCompatEditText getEd_postopic_title() {
        return (AppCompatEditText) this.ed_postopic_title.getValue();
    }

    @NotNull
    public final AppCompatEditText getEt_aivideochangeface_info() {
        return (AppCompatEditText) this.et_aivideochangeface_info.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_post_input;
    }

    @NotNull
    public final LinearLayout getLl_postimage() {
        return (LinearLayout) this.ll_postimage.getValue();
    }

    @NotNull
    public final LinearLayout getLl_posttopic_name() {
        return (LinearLayout) this.ll_posttopic_name.getValue();
    }

    @NotNull
    public final LinearLayout getLl_postvideo() {
        return (LinearLayout) this.ll_postvideo.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getRightTitle() {
        return "";
    }

    @NotNull
    public final RecyclerView getRv_image() {
        return (RecyclerView) this.rv_image.getValue();
    }

    @NotNull
    public final RecyclerView getRv_video() {
        return (RecyclerView) this.rv_video.getValue();
    }

    @Nullable
    public final ArrayList<TagSubBean> getTagsAll() {
        return this.tagsAll;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return (Intrinsics.areEqual(getIntoPage(), "") || !Intrinsics.areEqual(getIntoPage(), "video")) ? "发布帖子" : "上传视频";
    }

    @NotNull
    public final TextView getTv_media_title() {
        return (TextView) this.tv_media_title.getValue();
    }

    @NotNull
    public final TextView getTv_media_video_tips() {
        return (TextView) this.tv_media_video_tips.getValue();
    }

    @NotNull
    public final TextView getTv_tags_selected() {
        return (TextView) this.tv_tags_selected.getValue();
    }

    @NotNull
    public final String getUploadBaseUrl() {
        return this.uploadBaseUrl;
    }

    @NotNull
    public final String getUploadImgBaseUrl() {
        return this.uploadImgBaseUrl;
    }

    @NotNull
    public final String getUploadImgToken() {
        return this.uploadImgToken;
    }

    @NotNull
    public final String getUploadToken() {
        return this.uploadToken;
    }

    @NotNull
    public final String getUploadVideoBaseUrl() {
        return this.uploadVideoBaseUrl;
    }

    @NotNull
    public final String getUploadVideoToken() {
        return this.uploadVideoToken;
    }

    public final void setCurTags(@Nullable ArrayList<TagSubBean> arrayList) {
        this.curTags = arrayList;
    }

    public final void setTagsAll(@Nullable ArrayList<TagSubBean> arrayList) {
        this.tagsAll = arrayList;
    }

    public final void setUploadBaseUrl(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.uploadBaseUrl = str;
    }

    public final void setUploadImgBaseUrl(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.uploadImgBaseUrl = str;
    }

    public final void setUploadImgToken(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.uploadImgToken = str;
    }

    public final void setUploadToken(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.uploadToken = str;
    }

    public final void setUploadVideoBaseUrl(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.uploadVideoBaseUrl = str;
    }

    public final void setUploadVideoToken(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.uploadVideoToken = str;
    }

    @NotNull
    public final PostViewModel viewModelInstance() {
        return getViewModel();
    }
}

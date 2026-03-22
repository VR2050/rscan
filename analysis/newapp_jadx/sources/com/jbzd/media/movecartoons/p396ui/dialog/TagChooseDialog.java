package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Activity;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.p396ui.dialog.TagChooseDialog;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import com.qunidayede.supportlibrary.widget.ClearEditText;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\r\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\n*\u00020E\u0018\u0000 L2\u00020\u0001:\u0002LMB\u001f\u0012\u0006\u0010.\u001a\u00020-\u0012\u0006\u0010H\u001a\u00020\u000b\u0012\u0006\u0010I\u001a\u00020\u000b¢\u0006\u0004\bJ\u0010KJ\u0015\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0015\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002H\u0002¢\u0006\u0004\b\u0006\u0010\u0005J\u0017\u0010\t\u001a\u00020\b2\u0006\u0010\u0007\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\t\u0010\nJ\u001f\u0010\u000e\u001a\u00020\r2\u0006\u0010\u0007\u001a\u00020\u00032\u0006\u0010\f\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ\u001f\u0010\u0010\u001a\u00020\r2\u0006\u0010\u0007\u001a\u00020\u00032\u0006\u0010\f\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\u0010\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\rH\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\u0017\u0010\u0015\u001a\u00020\r2\b\u0010\u0014\u001a\u0004\u0018\u00010\u0013¢\u0006\u0004\b\u0015\u0010\u0016J)\u0010\u0019\u001a\u00020\r2\f\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00030\u00022\f\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002¢\u0006\u0004\b\u0019\u0010\u001aJ+\u0010\u001d\u001a\b\u0012\u0004\u0012\u00020\u00030\u00022\f\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00030\u00022\b\u0010\u001c\u001a\u0004\u0018\u00010\u001b¢\u0006\u0004\b\u001d\u0010\u001eJ\r\u0010\u001f\u001a\u00020\r¢\u0006\u0004\b\u001f\u0010\u0012J\u000f\u0010 \u001a\u00020\rH\u0016¢\u0006\u0004\b \u0010\u0012R%\u0010'\u001a\n \"*\u0004\u0018\u00010!0!8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b#\u0010$\u001a\u0004\b%\u0010&R%\u0010,\u001a\n \"*\u0004\u0018\u00010(0(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b)\u0010$\u001a\u0004\b*\u0010+R\u0016\u0010.\u001a\u00020-8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b.\u0010/R\u0016\u00101\u001a\u0002008\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b1\u00102R\u0018\u00103\u001a\u0004\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b3\u00104R%\u00109\u001a\n \"*\u0004\u0018\u000105058B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b6\u0010$\u001a\u0004\b7\u00108R%\u0010<\u001a\n \"*\u0004\u0018\u000105058B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b:\u0010$\u001a\u0004\b;\u00108R%\u0010?\u001a\n \"*\u0004\u0018\u00010!0!8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b=\u0010$\u001a\u0004\b>\u0010&R%\u0010D\u001a\n \"*\u0004\u0018\u00010@0@8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bA\u0010$\u001a\u0004\bB\u0010CR\u0016\u0010F\u001a\u00020E8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bF\u0010G¨\u0006N"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/StrongBottomSheetDialog;", "", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "getSelectedTags", "()Ljava/util/List;", "getAllTags", "tag", "", "contain", "(Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;)Z", "", "position", "", "clickSelectTag", "(Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;I)V", "clickAllTag", "initDefaultShow", "()V", "Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$EventListener;", "eventListener", "setEventListener", "(Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$EventListener;)V", "allTags", "selectTags", "setShowData", "(Ljava/util/List;Ljava/util/List;)V", "", "keywords", "filterKeywords", "(Ljava/util/List;Ljava/lang/CharSequence;)Ljava/util/List;", "init", "dismiss", "Landroid/widget/ImageView;", "kotlin.jvm.PlatformType", "btn_confirm$delegate", "Lkotlin/Lazy;", "getBtn_confirm", "()Landroid/widget/ImageView;", "btn_confirm", "Lcom/qunidayede/supportlibrary/widget/ClearEditText;", "cet_num$delegate", "getCet_num", "()Lcom/qunidayede/supportlibrary/widget/ClearEditText;", "cet_num", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "com/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$mSelectedTagAdapter$1", "mSelectedTagAdapter", "Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$mSelectedTagAdapter$1;", "listener", "Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$EventListener;", "Landroidx/recyclerview/widget/RecyclerView;", "rv_selected$delegate", "getRv_selected", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_selected", "rv_tags$delegate", "getRv_tags", "rv_tags", "iv_close$delegate", "getIv_close", "iv_close", "Landroid/view/View;", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "com/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$mAllTagAdapter$1", "mAllTagAdapter", "Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$mAllTagAdapter$1;", "peekHeight", "maxHeight", "<init>", "(Landroid/app/Activity;II)V", "Companion", "EventListener", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TagChooseDialog extends StrongBottomSheetDialog {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: btn_confirm$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_confirm;

    /* renamed from: cet_num$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy cet_num;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Activity context;

    /* renamed from: iv_close$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_close;

    @Nullable
    private EventListener listener;

    @NotNull
    private final TagChooseDialog$mAllTagAdapter$1 mAllTagAdapter;

    @NotNull
    private final TagChooseDialog$mSelectedTagAdapter$1 mSelectedTagAdapter;

    /* renamed from: rv_selected$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_selected;

    /* renamed from: rv_tags$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_tags;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$Companion;", "", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog;", "getTagChooseDialog", "(Landroid/app/Activity;)Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final TagChooseDialog getTagChooseDialog(@NotNull Activity activity) {
            View findViewById;
            Intrinsics.checkNotNullParameter(activity, "activity");
            int m2513s0 = (C2354n.m2513s0(activity) * 6) / 7;
            TagChooseDialog tagChooseDialog = new TagChooseDialog(activity, m2513s0, m2513s0);
            tagChooseDialog.init();
            Window window = tagChooseDialog.getWindow();
            if (window != null && (findViewById = window.findViewById(R.id.design_bottom_sheet)) != null) {
                findViewById.setBackgroundResource(android.R.color.transparent);
            }
            return tagChooseDialog;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u001d\u0010\u0006\u001a\u00020\u00052\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002H&¢\u0006\u0004\b\u0006\u0010\u0007¨\u0006\b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/TagChooseDialog$EventListener;", "", "", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "selectTags", "", "onConfirm", "(Ljava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public interface EventListener {
        void onConfirm(@NotNull List<? extends TagBean> selectTags);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Type inference failed for: r2v13, types: [com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$mAllTagAdapter$1] */
    /* JADX WARN: Type inference failed for: r2v14, types: [com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$mSelectedTagAdapter$1] */
    public TagChooseDialog(@NotNull Activity context, int i2, int i3) {
        super(context, i2, i3, R.style.TransBottomSheetDialogStyle);
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                Activity activity;
                activity = TagChooseDialog.this.context;
                return LayoutInflater.from(activity).inflate(R.layout.dialog_sms_choose, (ViewGroup) null);
            }
        });
        this.rv_selected = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$rv_selected$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final RecyclerView invoke() {
                View contentView;
                contentView = TagChooseDialog.this.getContentView();
                return (RecyclerView) contentView.findViewById(R.id.rv_selected);
            }
        });
        this.rv_tags = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$rv_tags$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final RecyclerView invoke() {
                View contentView;
                contentView = TagChooseDialog.this.getContentView();
                return (RecyclerView) contentView.findViewById(R.id.rv_tags);
            }
        });
        this.btn_confirm = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$btn_confirm$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final ImageView invoke() {
                View contentView;
                contentView = TagChooseDialog.this.getContentView();
                return (ImageView) contentView.findViewById(R.id.itv_confirm_post);
            }
        });
        this.iv_close = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$iv_close$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final ImageView invoke() {
                View contentView;
                contentView = TagChooseDialog.this.getContentView();
                return (ImageView) contentView.findViewById(R.id.iv_close);
            }
        });
        this.cet_num = LazyKt__LazyJVMKt.lazy(new Function0<ClearEditText>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$cet_num$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final ClearEditText invoke() {
                View contentView;
                contentView = TagChooseDialog.this.getContentView();
                return (ClearEditText) contentView.findViewById(R.id.cet_num);
            }
        });
        this.mAllTagAdapter = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$mAllTagAdapter$1
            {
                super(R.layout.item_home_tag, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
                boolean contain;
                boolean contain2;
                boolean contain3;
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                TagChooseDialog tagChooseDialog = TagChooseDialog.this;
                String str = item.name;
                if (str == null) {
                    str = "";
                }
                helper.m3919i(R.id.tv_name, str);
                TextView textView = (TextView) helper.m3912b(R.id.tv_name);
                contain = tagChooseDialog.contain(item);
                textView.setSelected(contain);
                LinearLayout linearLayout = (LinearLayout) helper.m3912b(R.id.ll_parent);
                contain2 = tagChooseDialog.contain(item);
                linearLayout.setSelected(contain2);
                ImageView imageView = (ImageView) helper.m3912b(R.id.iv_del);
                contain3 = tagChooseDialog.contain(item);
                imageView.setVisibility(contain3 ? 0 : 8);
            }
        };
        this.mSelectedTagAdapter = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$mSelectedTagAdapter$1
            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                String str = item.name;
                if (str == null) {
                    str = "";
                }
                helper.m3919i(R.id.tv_name, str);
                ((TextView) helper.m3912b(R.id.tv_name)).setSelected(true);
                ((LinearLayout) helper.m3912b(R.id.ll_parent)).setSelected(true);
                ((ImageView) helper.m3912b(R.id.iv_del)).setVisibility(0);
            }
        };
    }

    private final void clickAllTag(TagBean tag, int position) {
        if (!contain(tag)) {
            if (getSelectedTags().size() >= 8) {
                C2354n.m2449Z("最多选择8个标签");
                return;
            } else {
                addData((TagChooseDialog$mSelectedTagAdapter$1) tag);
                notifyItemChanged(position);
                return;
            }
        }
        Iterator<TagBean> it = getSelectedTags().iterator();
        int i2 = 0;
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().f10032id, tag.f10032id)) {
                remove(i2);
                break;
            }
            i2 = i3;
        }
        notifyItemChanged(position);
    }

    private final void clickSelectTag(TagBean tag, int position) {
        remove(position);
        Iterator<TagBean> it = getAllTags().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().f10032id, tag.f10032id)) {
                notifyItemChanged(i2);
                return;
            }
            i2 = i3;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean contain(TagBean tag) {
        Iterator<TagBean> it = getSelectedTags().iterator();
        while (it.hasNext()) {
            if (TextUtils.equals(it.next().f10032id, tag.f10032id)) {
                return true;
            }
        }
        return false;
    }

    private final List<TagBean> getAllTags() {
        return getData();
    }

    private final ImageView getBtn_confirm() {
        return (ImageView) this.btn_confirm.getValue();
    }

    private final ClearEditText getCet_num() {
        return (ClearEditText) this.cet_num.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final ImageView getIv_close() {
        return (ImageView) this.iv_close.getValue();
    }

    private final RecyclerView getRv_selected() {
        return (RecyclerView) this.rv_selected.getValue();
    }

    private final RecyclerView getRv_tags() {
        return (RecyclerView) this.rv_tags.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<TagBean> getSelectedTags() {
        return getData();
    }

    private final void initDefaultShow() {
        RecyclerView rv_tags = getRv_tags();
        rv_tags.setLayoutManager(new GridLayoutManager(rv_tags.getContext(), 4));
        if (rv_tags.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_tags.getContext());
            c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_tags, 7.5d);
            c4053a.f10337e = C2354n.m2437V(rv_tags.getContext(), 2.5d);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            C1499a.m604Z(c4053a, rv_tags);
        }
        rv_tags.setAdapter(this.mAllTagAdapter);
        RecyclerView rv_selected = getRv_selected();
        rv_selected.setLayoutManager(new GridLayoutManager(rv_selected.getContext(), 4));
        if (rv_selected.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(rv_selected.getContext());
            c4053a2.f10336d = C1499a.m638x(c4053a2, R.color.transparent, rv_selected, 7.5d);
            c4053a2.f10337e = C2354n.m2437V(rv_selected.getContext(), 2.5d);
            c4053a2.f10339g = false;
            c4053a2.f10340h = false;
            c4053a2.f10338f = false;
            C1499a.m604Z(c4053a2, rv_selected);
        }
        rv_selected.setAdapter(this.mSelectedTagAdapter);
        setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.a0
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                TagChooseDialog.m5791initDefaultShow$lambda2(TagChooseDialog.this, baseQuickAdapter, view, i2);
            }
        });
        setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.b0
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                TagChooseDialog.m5792initDefaultShow$lambda3(TagChooseDialog.this, baseQuickAdapter, view, i2);
            }
        });
        C2354n.m2374A(getBtn_confirm(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$initDefaultShow$5
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView) {
                TagChooseDialog.EventListener eventListener;
                List<? extends TagBean> selectedTags;
                TagChooseDialog.this.dismiss();
                eventListener = TagChooseDialog.this.listener;
                if (eventListener == null) {
                    return;
                }
                selectedTags = TagChooseDialog.this.getSelectedTags();
                eventListener.onConfirm(selectedTags);
            }
        }, 1);
        C2354n.m2374A(getIv_close(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$initDefaultShow$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView) {
                TagChooseDialog.this.dismiss();
            }
        }, 1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initDefaultShow$lambda-2, reason: not valid java name */
    public static final void m5791initDefaultShow$lambda2(TagChooseDialog this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
        this$0.clickAllTag((TagBean) obj, i2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initDefaultShow$lambda-3, reason: not valid java name */
    public static final void m5792initDefaultShow$lambda3(TagChooseDialog this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
        this$0.clickSelectTag((TagBean) obj, i2);
    }

    @Override // androidx.appcompat.app.AppCompatDialog, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        View currentFocus = getCurrentFocus();
        if (currentFocus instanceof EditText) {
            C2861e.m3306d(currentFocus);
        }
        super.dismiss();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @NotNull
    public final List<TagBean> filterKeywords(@NotNull List<? extends TagBean> allTags, @Nullable CharSequence keywords) {
        Intrinsics.checkNotNullParameter(allTags, "allTags");
        if (keywords == null || keywords.length() == 0) {
            return allTags;
        }
        ArrayList arrayList = new ArrayList();
        for (TagBean tagBean : allTags) {
            String str = tagBean.name;
            boolean contains = str == null ? false : StringsKt__StringsKt.contains((CharSequence) str, keywords, true);
            String str2 = tagBean.first_letter;
            boolean contains2 = str2 == null ? false : StringsKt__StringsKt.contains((CharSequence) str2, keywords, true);
            if (contains || contains2) {
                arrayList.add(tagBean);
            }
        }
        return arrayList;
    }

    public final void init() {
        setContentView(getContentView());
        initDefaultShow();
    }

    public final void setEventListener(@Nullable EventListener eventListener) {
        this.listener = eventListener;
    }

    public final void setShowData(@NotNull final List<? extends TagBean> allTags, @NotNull List<? extends TagBean> selectTags) {
        Intrinsics.checkNotNullParameter(allTags, "allTags");
        Intrinsics.checkNotNullParameter(selectTags, "selectTags");
        setNewData(null);
        setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) selectTags));
        setNewData(null);
        setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) allTags));
        getCet_num().addTextChangedListener(new TextWatcher() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagChooseDialog$setShowData$1
            @Override // android.text.TextWatcher
            public void afterTextChanged(@Nullable Editable s) {
            }

            @Override // android.text.TextWatcher
            public void beforeTextChanged(@Nullable CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(@Nullable CharSequence s, int start, int before, int count) {
                TagChooseDialog$mAllTagAdapter$1 tagChooseDialog$mAllTagAdapter$1;
                tagChooseDialog$mAllTagAdapter$1 = TagChooseDialog.this.mAllTagAdapter;
                tagChooseDialog$mAllTagAdapter$1.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) TagChooseDialog.this.filterKeywords(allTags, s)));
            }
        });
    }
}

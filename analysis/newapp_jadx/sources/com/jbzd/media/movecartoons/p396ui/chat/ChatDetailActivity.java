package com.jbzd.media.movecartoons.p396ui.chat;

import android.content.Context;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.text.Editable;
import android.view.View;
import android.view.Window;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.UploadPicResponse;
import com.jbzd.media.movecartoons.bean.request.ChatRequest;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import com.jbzd.media.movecartoons.bean.response.FaqBean;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.jbzd.media.movecartoons.databinding.ChatDetailActBinding;
import com.jbzd.media.movecartoons.databinding.ItemChatLogProblemBinding;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.preview.PreviewImageActivity;
import com.luck.picture.lib.PictureSelector;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__MutableCollectionsJVMKt;
import kotlin.comparisons.ComparisonsKt__ComparisonsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.Reflection;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0847g0;
import p005b.p006a.p007a.p008a.p009a.C0875w;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p006a.p007a.p008a.p017r.p021n.C0945b;
import p005b.p006a.p007a.p008a.p017r.p022o.C0949c;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;
import p005b.p327w.p330b.p337d.ViewTreeObserverOnGlobalLayoutListenerC2860d;
import p379c.p380a.InterfaceC3053d1;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000V\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0017\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u0000 ?2\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0001?B\u0007¢\u0006\u0004\b>\u0010\u0006J\u000f\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J!\u0010\u000b\u001a\u00020\u00042\b\u0010\b\u001a\u0004\u0018\u00010\u00072\u0006\u0010\n\u001a\u00020\tH\u0002¢\u0006\u0004\b\u000b\u0010\fJQ\u0010\u0015\u001a\u00020\u00042\b\u0010\r\u001a\u0004\u0018\u00010\u00072\u0006\u0010\u000e\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00072\b\b\u0002\u0010\u0011\u001a\u00020\u00102\n\b\u0002\u0010\u0012\u001a\u0004\u0018\u00010\u00072\u0010\b\u0002\u0010\u0014\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0013H\u0002¢\u0006\u0004\b\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0017\u0010\u0006J:\u0010\u001f\u001a\u00020\u00042\u0006\u0010\u0018\u001a\u00020\u00072!\u0010\u001e\u001a\u001d\u0012\u0013\u0012\u00110\u001a¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001d\u0012\u0004\u0012\u00020\u00040\u0019H\u0002¢\u0006\u0004\b\u001f\u0010 J\u000f\u0010!\u001a\u00020\u0007H\u0016¢\u0006\u0004\b!\u0010\"J\u000f\u0010#\u001a\u00020\u0004H\u0016¢\u0006\u0004\b#\u0010\u0006J\u000f\u0010$\u001a\u00020\u0004H\u0016¢\u0006\u0004\b$\u0010\u0006J\u000f\u0010%\u001a\u00020\u0004H\u0014¢\u0006\u0004\b%\u0010\u0006R\u001f\u0010)\u001a\u0004\u0018\u00010\u00078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b&\u0010'\u001a\u0004\b(\u0010\"R\u001f\u0010,\u001a\u0004\u0018\u00010\u00078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b*\u0010'\u001a\u0004\b+\u0010\"R\u001f\u0010/\u001a\u0004\u0018\u00010\u00078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b-\u0010'\u001a\u0004\b.\u0010\"R\u001d\u00102\u001a\u00020\u00078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u0010'\u001a\u0004\b1\u0010\"R\u001d\u00107\u001a\u0002038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b4\u0010'\u001a\u0004\b5\u00106R\u001d\u0010:\u001a\u00020\u00078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b8\u0010'\u001a\u0004\b9\u0010\"R\u0018\u0010<\u001a\u0004\u0018\u00010;8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b<\u0010=¨\u0006@"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/chat/ChatDetailActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ChatDetailActBinding;", "Lcom/jbzd/media/movecartoons/ui/chat/ChatViewModel;", "", "request", "()V", "", "headImage", "Lcom/jbzd/media/movecartoons/bean/response/FaqBean$FaqItem;", "faqItem", "faqClick", "(Ljava/lang/String;Lcom/jbzd/media/movecartoons/bean/response/FaqBean$FaqItem;)V", "userId", "content", "type", "", "handleError", "ext", "Lkotlin/Function0;", "callback", "sendMessage", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Lkotlin/jvm/functions/Function0;)V", "chooseImage", "filePath", "Lkotlin/Function1;", "Lcom/jbzd/media/movecartoons/bean/UploadPicResponse$DataBean;", "Lkotlin/ParameterName;", "name", "dataBean", "uploadCoverSuccess", "uploadCover", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "getTopBarTitle", "()Ljava/lang/String;", "initView", "bindEvent", "onDestroy", "title$delegate", "Lkotlin/Lazy;", "getTitle", VideoListActivity.KEY_TITLE, "orderSn$delegate", "getOrderSn", "orderSn", "orderPrice$delegate", "getOrderPrice", "orderPrice", "faqType$delegate", "getFaqType", "faqType", "Lb/a/a/a/r/n/a;", "repository$delegate", "getRepository", "()Lb/a/a/a/r/n/a;", "repository", "chatId$delegate", "getChatId", "chatId", "Lc/a/d1;", "jobForUploadCover", "Lc/a/d1;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ChatDetailActivity extends BaseVMActivity<ChatDetailActBinding, ChatViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_CHAT_ID = "KEY_CHAT_ID";

    @NotNull
    public static final String KEY_CHAT_PRICE = "KEY_CHAT_PRICE";

    @NotNull
    public static final String KEY_CHAT_TITLE = "KEY_CHAT_TITLE";

    @NotNull
    public static final String KEY_ORDER_SN = "KEY_ORDER_SN";

    @NotNull
    public static final String KEY_TRADE_DETAIL = "KEY_TRADE_DETAIL";

    @Nullable
    private InterfaceC3053d1 jobForUploadCover;

    /* renamed from: chatId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy chatId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$chatId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = ChatDetailActivity.this.getIntent().getStringExtra(ChatDetailActivity.KEY_CHAT_ID);
            return stringExtra == null ? ChatMsgBean.SERVICE_ID : stringExtra;
        }
    });

    /* renamed from: title$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy title = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$title$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ChatDetailActivity.this.getIntent().getStringExtra(ChatDetailActivity.KEY_CHAT_TITLE);
        }
    });

    /* renamed from: orderSn$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy orderSn = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$orderSn$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ChatDetailActivity.this.getIntent().getStringExtra(ChatDetailActivity.KEY_ORDER_SN);
        }
    });

    /* renamed from: orderPrice$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy orderPrice = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$orderPrice$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ChatDetailActivity.this.getIntent().getStringExtra(ChatDetailActivity.KEY_CHAT_PRICE);
        }
    });

    /* renamed from: repository$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy repository = LazyKt__LazyJVMKt.lazy(new Function0<C0944a>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$repository$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0944a invoke() {
            return new C0944a();
        }
    });

    /* renamed from: faqType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy faqType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$faqType$2
        {
            super(0);
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
        java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
        	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
        	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterative(DepthRegionTraversal.java:31)
        	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visit(SwitchOverStringVisitor.java:60)
         */
        /* JADX WARN: Removed duplicated region for block: B:13:0x0032 A[ORIG_RETURN, RETURN] */
        @Override // kotlin.jvm.functions.Function0
        @org.jetbrains.annotations.NotNull
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final java.lang.String invoke() {
            /*
                r2 = this;
                com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity r0 = com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity.this
                java.lang.String r0 = com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity.access$getChatId(r0)
                int r1 = r0.hashCode()
                switch(r1) {
                    case 1446: goto L26;
                    case 1447: goto L1a;
                    case 1448: goto Le;
                    default: goto Ld;
                }
            Ld:
                goto L32
            Le:
                java.lang.String r1 = "-5"
                boolean r0 = r0.equals(r1)
                if (r0 != 0) goto L17
                goto L32
            L17:
                java.lang.String r0 = "faq_money"
                goto L34
            L1a:
                java.lang.String r1 = "-4"
                boolean r0 = r0.equals(r1)
                if (r0 != 0) goto L23
                goto L32
            L23:
                java.lang.String r0 = "faq_dating"
                goto L34
            L26:
                java.lang.String r1 = "-3"
                boolean r0 = r0.equals(r1)
                if (r0 != 0) goto L2f
                goto L32
            L2f:
                java.lang.String r0 = "faq_nude"
                goto L34
            L32:
                java.lang.String r0 = "faq"
            L34:
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity$faqType$2.invoke():java.lang.String");
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0012\u0010\u0013JA\u0010\n\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u0010\u0005\u001a\u00020\u00042\b\b\u0002\u0010\u0006\u001a\u00020\u00042\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u00042\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u0004¢\u0006\u0004\b\n\u0010\u000bR\u0016\u0010\f\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\f\u0010\rR\u0016\u0010\u000e\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000e\u0010\rR\u0016\u0010\u000f\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000f\u0010\rR\u0016\u0010\u0010\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0010\u0010\rR\u0016\u0010\u0011\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0011\u0010\r¨\u0006\u0014"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/chat/ChatDetailActivity$Companion;", "", "Landroid/content/Context;", "context", "", "chatId", VideoListActivity.KEY_TITLE, "orderSn", "orderPrice", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", ChatDetailActivity.KEY_CHAT_ID, "Ljava/lang/String;", ChatDetailActivity.KEY_CHAT_PRICE, ChatDetailActivity.KEY_CHAT_TITLE, ChatDetailActivity.KEY_ORDER_SN, ChatDetailActivity.KEY_TRADE_DETAIL, "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void start$default(Companion companion, Context context, String str, String str2, String str3, String str4, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                str = ChatMsgBean.SERVICE_ID;
            }
            String str5 = str;
            if ((i2 & 4) != 0) {
                str2 = context.getString(R.string.mine_online_service);
                Intrinsics.checkNotNullExpressionValue(str2, "fun start(\n            context: Context,\n            chatId: String = ChatMsgBean.SERVICE_ID,\n            title: String = context.getString(R.string.mine_online_service),\n            orderSn: String? = \"\",\n            orderPrice: String? = \"\"\n        ) {\n            context.startActivity(Intent(context, ChatDetailActivity::class.java).apply {\n                putExtra(KEY_CHAT_ID, chatId)\n                putExtra(KEY_CHAT_TITLE, title)\n                putExtra(KEY_ORDER_SN, orderSn)\n                putExtra(KEY_CHAT_PRICE, orderPrice)\n            })\n        }");
            }
            companion.start(context, str5, str2, (i2 & 8) != 0 ? "" : str3, (i2 & 16) != 0 ? "" : str4);
        }

        public final void start(@NotNull Context context, @NotNull String chatId, @NotNull String title, @Nullable String orderSn, @Nullable String orderPrice) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(chatId, "chatId");
            Intrinsics.checkNotNullParameter(title, "title");
            Intent intent = new Intent(context, (Class<?>) ChatDetailActivity.class);
            intent.putExtra(ChatDetailActivity.KEY_CHAT_ID, chatId);
            intent.putExtra(ChatDetailActivity.KEY_CHAT_TITLE, title);
            intent.putExtra(ChatDetailActivity.KEY_ORDER_SN, orderSn);
            intent.putExtra(ChatDetailActivity.KEY_CHAT_PRICE, orderPrice);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final /* synthetic */ ChatDetailActBinding access$getBodyBinding(ChatDetailActivity chatDetailActivity) {
        return (ChatDetailActBinding) chatDetailActivity.getBodyBinding();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void chooseImage() {
        PictureSelector.create(this).openGallery(PictureMimeType.ofImage()).imageEngine(C0875w.m204a()).selectionMode(1).isCompress(true).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$chooseImage$1
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                if (result == null || result.isEmpty()) {
                    return;
                }
                final String currentCoverPath = result.get(0).getCompressPath();
                ChatDetailActivity chatDetailActivity = ChatDetailActivity.this;
                Intrinsics.checkNotNullExpressionValue(currentCoverPath, "currentCoverPath");
                final ChatDetailActivity chatDetailActivity2 = ChatDetailActivity.this;
                chatDetailActivity.uploadCover(currentCoverPath, new Function1<UploadPicResponse.DataBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$chooseImage$1$onResult$1

                    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\b\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"", "<anonymous>", "()V"}, m5312k = 3, m5313mv = {1, 5, 1})
                    /* renamed from: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$chooseImage$1$onResult$1$1 */
                    public static final class C36561 extends Lambda implements Function0<Unit> {
                        public final /* synthetic */ ChatDetailActivity this$0;

                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        public C36561(ChatDetailActivity chatDetailActivity) {
                            super(0);
                            this.this$0 = chatDetailActivity;
                        }

                        /* JADX INFO: Access modifiers changed from: private */
                        /* renamed from: invoke$lambda-0, reason: not valid java name */
                        public static final void m5747invoke$lambda0(ChatDetailActivity this$0) {
                            Intrinsics.checkNotNullParameter(this$0, "this$0");
                            RecyclerView recyclerView = ChatDetailActivity.access$getBodyBinding(this$0).list;
                            Intrinsics.checkNotNullExpressionValue(ChatDetailActivity.access$getBodyBinding(this$0).list, "bodyBinding.list");
                            recyclerView.smoothScrollToPosition(C4195m.m4793Z(r2).m3931h() - 1);
                        }

                        @Override // kotlin.jvm.functions.Function0
                        public /* bridge */ /* synthetic */ Unit invoke() {
                            invoke2();
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2() {
                            this.this$0.request();
                            PageRefreshLayout pageRefreshLayout = ChatDetailActivity.access$getBodyBinding(this.this$0).pager;
                            final ChatDetailActivity chatDetailActivity = this.this$0;
                            pageRefreshLayout.postDelayed(
                            /*  JADX ERROR: Method code generation error
                                jadx.core.utils.exceptions.CodegenException: Error generate insn: 0x0016: INVOKE 
                                  (r0v3 'pageRefreshLayout' com.drake.brv.PageRefreshLayout)
                                  (wrap:java.lang.Runnable:0x0011: CONSTRUCTOR (r1v0 'chatDetailActivity' com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity A[DONT_INLINE]) A[MD:(com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity):void (m), WRAPPED] call: b.a.a.a.t.c.a.<init>(com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity):void type: CONSTRUCTOR)
                                  (800 long)
                                 VIRTUAL call: android.view.ViewGroup.postDelayed(java.lang.Runnable, long):boolean A[MD:(java.lang.Runnable, long):boolean (c)] in method: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$chooseImage$1$onResult$1.1.invoke():void, file: classes2.dex
                                	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:310)
                                	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:273)
                                	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:94)
                                	at jadx.core.dex.nodes.IBlock.generate(IBlock.java:15)
                                	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:66)
                                	at jadx.core.dex.regions.Region.generate(Region.java:35)
                                	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:66)
                                	at jadx.core.codegen.MethodGen.addRegionInsns(MethodGen.java:297)
                                	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:276)
                                	at jadx.core.codegen.ClassGen.addMethodCode(ClassGen.java:406)
                                	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:335)
                                	at jadx.core.codegen.ClassGen.lambda$addInnerClsAndMethods$3(ClassGen.java:301)
                                	at java.base/java.util.stream.ForEachOps$ForEachOp$OfRef.accept(ForEachOps.java:184)
                                	at java.base/java.util.ArrayList.forEach(ArrayList.java:1596)
                                	at java.base/java.util.stream.SortedOps$RefSortingSink.end(SortedOps.java:395)
                                	at java.base/java.util.stream.Sink$ChainedReference.end(Sink.java:261)
                                Caused by: jadx.core.utils.exceptions.JadxRuntimeException: Expected class to be processed at this point, class: b.a.a.a.t.c.a, state: NOT_LOADED
                                	at jadx.core.dex.nodes.ClassNode.ensureProcessed(ClassNode.java:305)
                                	at jadx.core.codegen.InsnGen.inlineAnonymousConstructor(InsnGen.java:807)
                                	at jadx.core.codegen.InsnGen.makeConstructor(InsnGen.java:730)
                                	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:418)
                                	at jadx.core.codegen.InsnGen.addWrappedArg(InsnGen.java:145)
                                	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:121)
                                	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:108)
                                	at jadx.core.codegen.InsnGen.generateMethodArguments(InsnGen.java:1143)
                                	at jadx.core.codegen.InsnGen.makeInvoke(InsnGen.java:910)
                                	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:422)
                                	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:303)
                                	... 15 more
                                */
                            /*
                                this = this;
                                com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity r0 = r5.this$0
                                com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity.access$request(r0)
                                com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity r0 = r5.this$0
                                com.jbzd.media.movecartoons.databinding.ChatDetailActBinding r0 = com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity.access$getBodyBinding(r0)
                                com.drake.brv.PageRefreshLayout r0 = r0.pager
                                com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity r1 = r5.this$0
                                b.a.a.a.t.c.a r2 = new b.a.a.a.t.c.a
                                r2.<init>(r1)
                                r3 = 800(0x320, double:3.953E-321)
                                r0.postDelayed(r2, r3)
                                return
                            */
                            throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity$chooseImage$1$onResult$1.C36561.invoke2():void");
                        }
                    }

                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                        String chatId;
                        Intrinsics.checkNotNullParameter(it, "it");
                        ChatDetailActivity.this.hideLoading();
                        BitmapFactory.Options options = new BitmapFactory.Options();
                        options.inJustDecodeBounds = true;
                        BitmapFactory.decodeFile(currentCoverPath, options);
                        int i2 = options.outWidth;
                        int i3 = options.outHeight;
                        ChatDetailActivity chatDetailActivity3 = ChatDetailActivity.this;
                        chatId = chatDetailActivity3.getChatId();
                        String file = it.getFile();
                        Intrinsics.checkNotNullExpressionValue(file, "it.file");
                        StringBuilder sb = new StringBuilder();
                        sb.append(i2);
                        sb.append('*');
                        sb.append(i3);
                        ChatDetailActivity.sendMessage$default(chatDetailActivity3, chatId, file, "image", false, sb.toString(), new C36561(ChatDetailActivity.this), 8, null);
                    }
                });
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public final void faqClick(String headImage, FaqBean.FaqItem faqItem) {
        ArrayList arrayList = new ArrayList();
        ChatMsgBean.MessageBean messageBean = new ChatMsgBean.MessageBean();
        MyApp myApp = MyApp.f9891f;
        UserInfoBean userInfoBean = MyApp.f9892g;
        String str = userInfoBean.f9992id;
        if (str == null) {
            str = "";
        }
        messageBean.user_id = str;
        messageBean.is_my = "y";
        String str2 = userInfoBean.img;
        if (str2 == null) {
            str2 = "";
        }
        messageBean.head_img = str2;
        String str3 = userInfoBean.nickname;
        if (str3 == null) {
            str3 = "";
        }
        messageBean.nickname = str3;
        messageBean.type = "text";
        messageBean.content = faqItem.title;
        messageBean.time_label = "刚刚";
        Unit unit = Unit.INSTANCE;
        arrayList.add(messageBean);
        ChatMsgBean.MessageBean messageBean2 = new ChatMsgBean.MessageBean();
        messageBean2.user_id = getChatId();
        messageBean2.head_img = headImage;
        messageBean2.is_my = "n";
        String title = getTitle();
        messageBean2.nickname = title != null ? title : "";
        messageBean2.type = "text";
        messageBean2.content = faqItem.content;
        messageBean2.time_label = "刚刚";
        arrayList.add(messageBean2);
        PageRefreshLayout pageRefreshLayout = ((ChatDetailActBinding) getBodyBinding()).pager;
        Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
        PageRefreshLayout.m3951z(pageRefreshLayout, arrayList, null, null, null, 14, null);
        RecyclerView recyclerView = ((ChatDetailActBinding) getBodyBinding()).list;
        Intrinsics.checkNotNullExpressionValue(((ChatDetailActBinding) getBodyBinding()).list, "bodyBinding.list");
        recyclerView.smoothScrollToPosition(C4195m.m4793Z(r0).m3931h() - 1);
        String str4 = MyApp.f9892g.user_id;
        String str5 = faqItem.content;
        Intrinsics.checkNotNullExpressionValue(str5, "faqItem.content");
        sendMessage$default(this, str4, str5, "text", true, null, null, 48, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getChatId() {
        return (String) this.chatId.getValue();
    }

    private final String getFaqType() {
        return (String) this.faqType.getValue();
    }

    private final String getOrderPrice() {
        return (String) this.orderPrice.getValue();
    }

    private final String getOrderSn() {
        return (String) this.orderSn.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final C0944a getRepository() {
        return (C0944a) this.repository.getValue();
    }

    private final String getTitle() {
        return (String) this.title.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void request() {
        C0944a repository = getRepository();
        C2354n.m2441W0(new C0945b(repository.m287a().m239I(1, getChatId(), null)), this, new Function1<ChatMsgBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$request$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ChatMsgBean chatMsgBean) {
                invoke2(chatMsgBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ChatMsgBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                List<ChatMsgBean.MessageBean> message = lifecycleLoadingDialog.getMessage();
                if (message != null && message.size() > 1) {
                    CollectionsKt__MutableCollectionsJVMKt.sortWith(message, new Comparator() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$request$1$invoke$$inlined$sortBy$1
                        /* JADX WARN: Multi-variable type inference failed */
                        @Override // java.util.Comparator
                        public final int compare(T t, T t2) {
                            String str = ((ChatMsgBean.MessageBean) t).f9939id;
                            Intrinsics.checkNotNullExpressionValue(str, "it.id");
                            Integer valueOf = Integer.valueOf(Integer.parseInt(str));
                            String str2 = ((ChatMsgBean.MessageBean) t2).f9939id;
                            Intrinsics.checkNotNullExpressionValue(str2, "it.id");
                            return ComparisonsKt__ComparisonsKt.compareValues(valueOf, Integer.valueOf(Integer.parseInt(str2)));
                        }
                    });
                }
                ArrayList arrayList = new ArrayList();
                FaqBean faqBean = lifecycleLoadingDialog.faqBean;
                if (faqBean != null) {
                    Intrinsics.checkNotNullExpressionValue(faqBean, "this.faqBean");
                    arrayList.add(faqBean);
                }
                if (Intrinsics.areEqual(lifecycleLoadingDialog.getMessage() == null ? null : Boolean.valueOf(!r0.isEmpty()), Boolean.TRUE)) {
                    List<ChatMsgBean.MessageBean> message2 = lifecycleLoadingDialog.getMessage();
                    Intrinsics.checkNotNullExpressionValue(message2, "this.message");
                    arrayList.addAll(message2);
                }
                PageRefreshLayout pageRefreshLayout = ChatDetailActivity.access$getBodyBinding(ChatDetailActivity.this).pager;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                PageRefreshLayout.m3951z(pageRefreshLayout, arrayList, null, null, new Function1<BindingAdapter, Boolean>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$request$1.2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Boolean invoke(BindingAdapter bindingAdapter) {
                        return Boolean.valueOf(invoke2(bindingAdapter));
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final boolean invoke2(@NotNull BindingAdapter addData) {
                        Intrinsics.checkNotNullParameter(addData, "$this$addData");
                        return false;
                    }
                }, 6, null);
            }
        }, false, null, 12);
    }

    private final void sendMessage(String userId, String content, String type, final boolean handleError, String ext, final Function0<Unit> callback) {
        C0944a repository = getRepository();
        ChatRequest request = new ChatRequest();
        request.setContent(content);
        request.setTo_user_id(userId);
        request.setType(type);
        request.setExt(ext);
        Unit unit = Unit.INSTANCE;
        Objects.requireNonNull(repository);
        Intrinsics.checkNotNullParameter(request, "request");
        C2354n.m2438V0(repository.m287a().m247f(request), this, false, new Function1<Throwable, Boolean>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$sendMessage$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                return handleError;
            }
        }, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$sendMessage$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Object lifecycle) {
                Intrinsics.checkNotNullParameter(lifecycle, "$this$lifecycle");
                Function0<Unit> function0 = callback;
                if (function0 == null) {
                    return;
                }
                function0.invoke();
            }
        }, 2);
    }

    public static /* synthetic */ void sendMessage$default(ChatDetailActivity chatDetailActivity, String str, String str2, String str3, boolean z, String str4, Function0 function0, int i2, Object obj) {
        chatDetailActivity.sendMessage(str, str2, str3, (i2 & 8) != 0 ? false : z, (i2 & 16) != 0 ? null : str4, (i2 & 32) != 0 ? null : function0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void uploadCover(String filePath, Function1<? super UploadPicResponse.DataBean, Unit> uploadCoverSuccess) {
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
        this.jobForUploadCover = new C0949c(substring, substring2, user_id, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$uploadCover$1
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
                ChatDetailActivity.this.hideLoading();
                C2354n.m2379B1(str5);
            }
        }, "1", null, 32).m291b(filePath, uploadCoverSuccess);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        Window window = getWindow();
        FrameLayout frameLayout = (FrameLayout) window.findViewById(android.R.id.content);
        View childAt = frameLayout.getChildAt(0);
        frameLayout.getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserverOnGlobalLayoutListenerC2860d(window, new int[]{C2861e.m3303a(window)}, childAt, childAt.getPaddingBottom()));
        ((ChatDetailActBinding) getBodyBinding()).pager.m3954D(new Function1<PageRefreshLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$bindEvent$1
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
                C0944a repository;
                String chatId;
                Intrinsics.checkNotNullParameter(onRefresh, "$this$onRefresh");
                repository = ChatDetailActivity.this.getRepository();
                int f8947t0 = onRefresh.getF8947T0();
                chatId = ChatDetailActivity.this.getChatId();
                C0945b c0945b = new C0945b(repository.m287a().m239I(f8947t0, chatId, null));
                final ChatDetailActivity chatDetailActivity = ChatDetailActivity.this;
                Function1<Throwable, Boolean> function1 = new Function1<Throwable, Boolean>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$bindEvent$1.1
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
                        PageRefreshLayout pageRefreshLayout = ChatDetailActivity.access$getBodyBinding(ChatDetailActivity.this).pager;
                        Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                        PageRefreshLayout.m3948B(pageRefreshLayout, false, false, 3, null);
                        return false;
                    }
                };
                final ChatDetailActivity chatDetailActivity2 = ChatDetailActivity.this;
                C2354n.m2438V0(c0945b, chatDetailActivity, false, function1, new Function1<ChatMsgBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$bindEvent$1.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(ChatMsgBean chatMsgBean) {
                        invoke2(chatMsgBean);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull ChatMsgBean lifecycle) {
                        Intrinsics.checkNotNullParameter(lifecycle, "$this$lifecycle");
                        PageRefreshLayout pageRefreshLayout = ChatDetailActivity.access$getBodyBinding(ChatDetailActivity.this).pager;
                        Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                        PageRefreshLayout.m3948B(pageRefreshLayout, false, false, 3, null);
                    }
                }, 2);
            }
        });
        request();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String title = getTitle();
        if (title != null) {
            return title;
        }
        String string = getString(R.string.mine_online_service);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.mine_online_service)");
        return string;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        C2354n.m2374A(((ChatDetailActBinding) getBodyBinding()).btnPic, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ChatDetailActivity.this.chooseImage();
            }
        }, 1);
        C2354n.m2374A(((ChatDetailActBinding) getBodyBinding()).btnSend, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                String chatId;
                Intrinsics.checkNotNullParameter(it, "it");
                Editable text = ChatDetailActivity.access$getBodyBinding(ChatDetailActivity.this).edInput.getText();
                Intrinsics.checkNotNullExpressionValue(text, "bodyBinding.edInput.text");
                final CharSequence trim = StringsKt__StringsKt.trim(text);
                if (!(trim.length() > 0)) {
                    C2354n.m2525w0("内容不能为空");
                    return;
                }
                ChatDetailActivity chatDetailActivity = ChatDetailActivity.this;
                chatId = chatDetailActivity.getChatId();
                String obj = trim.toString();
                final ChatDetailActivity chatDetailActivity2 = ChatDetailActivity.this;
                ChatDetailActivity.sendMessage$default(chatDetailActivity, chatId, obj, "text", false, null, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$2.1
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
                        PageRefreshLayout pageRefreshLayout = ChatDetailActivity.access$getBodyBinding(ChatDetailActivity.this).pager;
                        Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                        ChatMsgBean.MessageBean messageBean = new ChatMsgBean.MessageBean();
                        CharSequence charSequence = trim;
                        MyApp myApp = MyApp.f9891f;
                        UserInfoBean userInfoBean = MyApp.f9892g;
                        String str = userInfoBean.f9992id;
                        if (str == null) {
                            str = "";
                        }
                        messageBean.user_id = str;
                        messageBean.is_my = "y";
                        String str2 = userInfoBean.img;
                        if (str2 == null) {
                            str2 = "";
                        }
                        messageBean.head_img = str2;
                        String str3 = userInfoBean.nickname;
                        if (str3 == null) {
                            str3 = "";
                        }
                        messageBean.nickname = str3;
                        messageBean.type = "text";
                        messageBean.content = charSequence.toString();
                        messageBean.time_label = "刚刚";
                        Unit unit = Unit.INSTANCE;
                        PageRefreshLayout.m3951z(pageRefreshLayout, CollectionsKt__CollectionsJVMKt.listOf(messageBean), null, null, null, 14, null);
                        RecyclerView recyclerView = ChatDetailActivity.access$getBodyBinding(ChatDetailActivity.this).list;
                        Intrinsics.checkNotNullExpressionValue(ChatDetailActivity.access$getBodyBinding(ChatDetailActivity.this).list, "bodyBinding.list");
                        recyclerView.smoothScrollToPosition(C4195m.m4793Z(r1).m3931h() - 1);
                        ChatDetailActivity.access$getBodyBinding(ChatDetailActivity.this).edInput.setText("");
                    }
                }, 24, null);
            }
        }, 1);
        RecyclerView recyclerView = ((ChatDetailActBinding) getBodyBinding()).list;
        Intrinsics.checkNotNullExpressionValue(recyclerView, "bodyBinding.list");
        C4195m.m4835u0(recyclerView, 0, false, false, true, 7);
        C4195m.m4774J0(recyclerView, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$3
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView2) {
                invoke2(bindingAdapter, recyclerView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView2) {
                boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView2, "it", FaqBean.class);
                final int i2 = R.layout.item_chat_log_problem;
                if (m616f0) {
                    bindingAdapter.f8910l.put(Reflection.typeOf(FaqBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$3$invoke$$inlined$addType$1
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
                    bindingAdapter.f8909k.put(Reflection.typeOf(FaqBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$3$invoke$$inlined$addType$2
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
                C36581 c36581 = new Function2<ChatMsgBean.MessageBean, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$3.1
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Integer invoke(ChatMsgBean.MessageBean messageBean, Integer num) {
                        return Integer.valueOf(invoke(messageBean, num.intValue()));
                    }

                    public final int invoke(@NotNull ChatMsgBean.MessageBean addType, int i3) {
                        Intrinsics.checkNotNullParameter(addType, "$this$addType");
                        String str = addType.is_my;
                        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y") ? R.layout.item_chat_log_user : R.layout.item_chat_log_system;
                    }
                };
                if (Modifier.isInterface(ChatMsgBean.MessageBean.class.getModifiers())) {
                    bindingAdapter.f8910l.put(Reflection.typeOf(ChatMsgBean.MessageBean.class), (Function2) TypeIntrinsics.beforeCheckcastToFunctionOfArity(c36581, 2));
                } else {
                    bindingAdapter.f8909k.put(Reflection.typeOf(ChatMsgBean.MessageBean.class), (Function2) TypeIntrinsics.beforeCheckcastToFunctionOfArity(c36581, 2));
                }
                C36592 listener = new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$3.2
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                        invoke(bindingViewHolder, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                        Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                        PreviewImageActivity.INSTANCE.start(onClick.f8926b, 0, CollectionsKt__CollectionsJVMKt.listOf(((ChatMsgBean.MessageBean) onClick.m3942b()).content));
                    }
                };
                Objects.requireNonNull(bindingAdapter);
                Intrinsics.checkNotNullParameter(listener, "listener");
                bindingAdapter.f8911m.put(Integer.valueOf(R.id.iv_content_image), new Pair<>(listener, Boolean.FALSE));
                final ChatDetailActivity chatDetailActivity = ChatDetailActivity.this;
                bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$3.3
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
                        ItemChatLogProblemBinding itemChatLogProblemBinding;
                        Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                        if (onBind.getItemViewType() != R.layout.item_chat_log_problem) {
                            if (onBind.getItemViewType() == R.layout.item_chat_log_system || onBind.getItemViewType() == R.layout.item_chat_log_user) {
                                ChatMsgBean.MessageBean messageBean = (ChatMsgBean.MessageBean) onBind.m3942b();
                                C2354n.m2455a2(onBind.f8926b).m3298p(messageBean.head_img).m3292f0().m757R((ImageView) onBind.m3941a(R.id.iv_portrait));
                                TextView textView = (TextView) onBind.m3941a(R.id.tv_time);
                                String str = messageBean.time_label;
                                if (str == null) {
                                    str = "";
                                }
                                textView.setText(str);
                                ImageView imageView = (ImageView) onBind.m3941a(R.id.iv_content_image);
                                TextView textView2 = (TextView) onBind.m3941a(R.id.tv_content);
                                if (!messageBean.isImage()) {
                                    imageView.setVisibility(8);
                                    textView2.setVisibility(0);
                                    ((TextView) onBind.m3941a(R.id.tv_content)).setText(messageBean.content);
                                    return;
                                } else {
                                    imageView.setVisibility(0);
                                    textView2.setVisibility(8);
                                    C2354n.m2455a2(onBind.f8926b).m3298p(messageBean.content).m3292f0().m757R(imageView);
                                    ((TextView) onBind.m3941a(R.id.tv_content)).setText("");
                                    return;
                                }
                            }
                            return;
                        }
                        final FaqBean faqBean = (FaqBean) onBind.m3942b();
                        ViewBinding viewBinding = onBind.f8929e;
                        if (viewBinding == null) {
                            Object invoke = ItemChatLogProblemBinding.class.getMethod("bind", View.class).invoke(null, onBind.itemView);
                            Objects.requireNonNull(invoke, "null cannot be cast to non-null type com.jbzd.media.movecartoons.databinding.ItemChatLogProblemBinding");
                            itemChatLogProblemBinding = (ItemChatLogProblemBinding) invoke;
                            onBind.f8929e = itemChatLogProblemBinding;
                        } else {
                            Objects.requireNonNull(viewBinding, "null cannot be cast to non-null type com.jbzd.media.movecartoons.databinding.ItemChatLogProblemBinding");
                            itemChatLogProblemBinding = (ItemChatLogProblemBinding) viewBinding;
                        }
                        C2354n.m2455a2(onBind.f8926b).m3298p(faqBean.system_head_img).m3288b0().m757R((ImageView) onBind.m3941a(R.id.iv_portrait));
                        itemChatLogProblemBinding.rvProblems.setNestedScrollingEnabled(false);
                        RecyclerView recyclerView3 = itemChatLogProblemBinding.rvProblems;
                        Intrinsics.checkNotNullExpressionValue(recyclerView3, "binding.rvProblems");
                        C4195m.m4835u0(recyclerView3, 0, false, false, false, 15);
                        final ChatDetailActivity chatDetailActivity2 = ChatDetailActivity.this;
                        C4195m.m4774J0(recyclerView3, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity.initView.3.3.1
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(2);
                            }

                            @Override // kotlin.jvm.functions.Function2
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter2, RecyclerView recyclerView4) {
                                invoke2(bindingAdapter2, recyclerView4);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull BindingAdapter bindingAdapter2, @NotNull RecyclerView recyclerView4) {
                                boolean m616f02 = C1499a.m616f0(bindingAdapter2, "$this$setup", recyclerView4, "it", FaqBean.FaqItem.class);
                                final int i3 = R.layout.item_problem_title;
                                if (m616f02) {
                                    bindingAdapter2.f8910l.put(Reflection.typeOf(FaqBean.FaqItem.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$3$3$1$invoke$$inlined$addType$1
                                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                        {
                                            super(2);
                                        }

                                        @NotNull
                                        public final Integer invoke(@NotNull Object obj, int i4) {
                                            Intrinsics.checkNotNullParameter(obj, "$this$null");
                                            return Integer.valueOf(i3);
                                        }

                                        @Override // kotlin.jvm.functions.Function2
                                        public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                            return invoke(obj, num.intValue());
                                        }
                                    });
                                } else {
                                    bindingAdapter2.f8909k.put(Reflection.typeOf(FaqBean.FaqItem.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity$initView$3$3$1$invoke$$inlined$addType$2
                                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                        {
                                            super(2);
                                        }

                                        @NotNull
                                        public final Integer invoke(@NotNull Object obj, int i4) {
                                            Intrinsics.checkNotNullParameter(obj, "$this$null");
                                            return Integer.valueOf(i3);
                                        }

                                        @Override // kotlin.jvm.functions.Function2
                                        public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                            return invoke(obj, num.intValue());
                                        }
                                    });
                                }
                                bindingAdapter2.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity.initView.3.3.1.1
                                    @Override // kotlin.jvm.functions.Function1
                                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                                        invoke2(bindingViewHolder);
                                        return Unit.INSTANCE;
                                    }

                                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                                    public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind2) {
                                        Intrinsics.checkNotNullParameter(onBind2, "$this$onBind");
                                        TextView textView3 = (TextView) onBind2.m3941a(R.id.tv_title);
                                        textView3.setText(textView3.getContext().getString(R.string.content_with_index, Integer.valueOf((onBind2.getLayoutPosition() - onBind2.f8930f.m3929f()) + 1), ((FaqBean.FaqItem) onBind2.m3942b()).title));
                                    }
                                });
                                int[] iArr = {R.id.tv_title};
                                final ChatDetailActivity chatDetailActivity3 = ChatDetailActivity.this;
                                final FaqBean faqBean2 = faqBean;
                                bindingAdapter2.m3937n(iArr, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ChatDetailActivity.initView.3.3.1.2
                                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                    {
                                        super(2);
                                    }

                                    @Override // kotlin.jvm.functions.Function2
                                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                                        invoke(bindingViewHolder, num.intValue());
                                        return Unit.INSTANCE;
                                    }

                                    public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i4) {
                                        Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                                        ChatDetailActivity.this.faqClick(faqBean2.system_head_img, (FaqBean.FaqItem) onClick.m3942b());
                                    }
                                });
                            }
                        }).m3939q(faqBean.faq_items);
                        TextView textView3 = itemChatLogProblemBinding.tvTime;
                        C0847g0 c0847g0 = C0847g0.f249a;
                        Calendar calendar = Calendar.getInstance();
                        String string = C4195m.m4792Y().getString(R.string.format_today, new Object[]{Integer.valueOf(calendar.get(1)), Integer.valueOf(calendar.get(2) + 1), Integer.valueOf(calendar.get(5))});
                        Intrinsics.checkNotNullExpressionValue(string, "getApp().getString(\n            R.string.format_today,\n            calendar.get(Calendar.YEAR),\n            calendar.get(Calendar.MONTH) + 1,\n            calendar.get(Calendar.DAY_OF_MONTH)\n        )");
                        textView3.setText(string);
                    }
                });
            }
        });
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        InterfaceC3053d1 interfaceC3053d1 = this.jobForUploadCover;
        if (interfaceC3053d1 == null) {
            return;
        }
        C2354n.m2512s(interfaceC3053d1, null, 1, null);
    }
}

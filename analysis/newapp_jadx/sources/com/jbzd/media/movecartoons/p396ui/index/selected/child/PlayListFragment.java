package com.jbzd.media.movecartoons.p396ui.index.selected.child;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.text.TextUtils;
import android.util.ArrayMap;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.MutableLiveData;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.flexbox.FlexboxLayoutManager;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.event.EventLine;
import com.jbzd.media.movecartoons.bean.event.EventSubscription;
import com.jbzd.media.movecartoons.bean.event.EventVideoPlayProgress;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.UpgradePriceDialog;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment$spinnerAdapter$2;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment$tagAdapter$2;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.jbzd.media.movecartoons.p396ui.post.user.UserPostHomeActivity;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.layoutmanagergroup.viewpager.ViewPagerLayoutManager;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.jbzd.media.movecartoons.view.video.ListPlayerView;
import com.jbzd.media.movecartoons.view.video.MyVideoAllCallback;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import com.shuyu.gsyvideoplayer.utils.CommonUtil;
import com.shuyu.gsyvideoplayer.video.base.GSYBaseVideoPlayer;
import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.StringsKt__StringNumberConversionsKt;
import kotlin.text.StringsKt__StringsJVMKt;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p009a.C0855k0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p362y.p363a.C2920c;
import p005b.p362y.p363a.p366f.InterfaceC2927c;
import p379c.p380a.InterfaceC3053d1;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Ù\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0016\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0014\n\u0002\b\u0018\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005*\u0003v´\u0001\u0018\u0000 ½\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002½\u0001B\b¢\u0006\u0005\b¼\u0001\u0010;J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ%\u0010\u000e\u001a\u00020\u00062\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\n0\t2\u0006\u0010\r\u001a\u00020\fH\u0003¢\u0006\u0004\b\u000e\u0010\u000fJg\u0010\u001b\u001a\u00020\u00062\u0006\u0010\u0010\u001a\u00020\f2%\b\u0002\u0010\u0016\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0012¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0015\u0012\u0004\u0012\u00020\u00060\u00112'\b\u0002\u0010\u001a\u001a!\u0012\u0017\u0012\u00150\u0017j\u0002`\u0018¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0019\u0012\u0004\u0012\u00020\u00060\u0011H\u0002¢\u0006\u0004\b\u001b\u0010\u001cJg\u0010\u001d\u001a\u00020\u00062\u0006\u0010\u0010\u001a\u00020\f2%\b\u0002\u0010\u0016\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0012¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0015\u0012\u0004\u0012\u00020\u00060\u00112'\b\u0002\u0010\u001a\u001a!\u0012\u0017\u0012\u00150\u0017j\u0002`\u0018¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0019\u0012\u0004\u0012\u00020\u00060\u0011H\u0002¢\u0006\u0004\b\u001d\u0010\u001cJ\u0017\u0010\u001f\u001a\u00020\u00062\u0006\u0010\u001e\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u001f\u0010 J\u0017\u0010!\u001a\u00020\u00062\u0006\u0010\u001e\u001a\u00020\u0004H\u0002¢\u0006\u0004\b!\u0010 J\u0017\u0010#\u001a\u00020\u00042\u0006\u0010\"\u001a\u00020\fH\u0002¢\u0006\u0004\b#\u0010$J\u0019\u0010&\u001a\u00020\f2\b\u0010%\u001a\u0004\u0018\u00010\fH\u0002¢\u0006\u0004\b&\u0010'J\u0019\u0010(\u001a\u00020\f2\b\u0010%\u001a\u0004\u0018\u00010\fH\u0002¢\u0006\u0004\b(\u0010'J\u0017\u0010*\u001a\u00020\u00062\u0006\u0010)\u001a\u00020\u0002H\u0002¢\u0006\u0004\b*\u0010+J\u000f\u0010,\u001a\u00020\fH\u0002¢\u0006\u0004\b,\u0010-J\u0011\u0010.\u001a\u0004\u0018\u00010\fH\u0002¢\u0006\u0004\b.\u0010-JU\u00102\u001a\u00020\u00062\u0006\u0010\u0010\u001a\u00020\f2<\b\u0002\u00101\u001a6\u0012\u0015\u0012\u0013\u0018\u00010\u0004¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(0\u0012\u0015\u0012\u0013\u0018\u00010\u0002¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0003\u0012\u0004\u0012\u00020\u00060/H\u0002¢\u0006\u0004\b2\u00103J\u0017\u00105\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u000204H\u0002¢\u0006\u0004\b5\u00106J\u0011\u00108\u001a\u0004\u0018\u000107H\u0002¢\u0006\u0004\b8\u00109J\u000f\u0010:\u001a\u00020\u0006H\u0002¢\u0006\u0004\b:\u0010;J\u001f\u0010@\u001a\u00020\u00062\u0006\u0010=\u001a\u00020<2\u0006\u0010?\u001a\u00020>H\u0002¢\u0006\u0004\b@\u0010AJ\u000f\u0010B\u001a\u00020\u0004H\u0016¢\u0006\u0004\bB\u0010CJG\u0010I\u001a\u00020\u00062\b\u0010D\u001a\u0004\u0018\u00010\f2\"\u0010G\u001a\u001e\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\f0Ej\u000e\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\f`F2\n\b\u0002\u0010H\u001a\u0004\u0018\u00010\f¢\u0006\u0004\bI\u0010JJ\u000f\u0010K\u001a\u00020\u0006H\u0016¢\u0006\u0004\bK\u0010;J\u000f\u0010L\u001a\u00020<H\u0016¢\u0006\u0004\bL\u0010MJ\u001f\u0010P\u001a\u00020\u00062\u0006\u0010O\u001a\u00020N2\u0006\u0010)\u001a\u00020\u0002H\u0016¢\u0006\u0004\bP\u0010QJ\u0017\u0010T\u001a\u00020\u00062\u0006\u0010S\u001a\u00020RH\u0007¢\u0006\u0004\bT\u0010UJ\u0011\u0010W\u001a\u0004\u0018\u00010VH\u0016¢\u0006\u0004\bW\u0010XJ\u000f\u0010Z\u001a\u00020YH\u0016¢\u0006\u0004\bZ\u0010[J\u0015\u0010\\\u001a\u00020\u00062\u0006\u0010=\u001a\u00020<¢\u0006\u0004\b\\\u0010]J\u000f\u0010^\u001a\u00020\u0006H\u0016¢\u0006\u0004\b^\u0010;J\u000f\u0010_\u001a\u00020\u0006H\u0016¢\u0006\u0004\b_\u0010;J\u000f\u0010`\u001a\u00020\u0006H\u0016¢\u0006\u0004\b`\u0010;J\u0019\u0010c\u001a\u00020\u00062\b\u0010b\u001a\u0004\u0018\u00010aH\u0007¢\u0006\u0004\bc\u0010dJ\u000f\u0010e\u001a\u00020\u0006H\u0016¢\u0006\u0004\be\u0010;J\u000f\u0010f\u001a\u00020\u0006H\u0016¢\u0006\u0004\bf\u0010;R\"\u0010g\u001a\u00020<8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bg\u0010h\u001a\u0004\bi\u0010M\"\u0004\bj\u0010]R\u0016\u0010k\u001a\u00020<8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bk\u0010hR9\u0010p\u001a\u001e\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\f0Ej\u000e\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\f`F8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bl\u0010m\u001a\u0004\bn\u0010oR\"\u0010q\u001a\u00020<8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bq\u0010h\u001a\u0004\br\u0010M\"\u0004\bs\u0010]R\u0018\u0010t\u001a\u0004\u0018\u00010\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bt\u0010uR\u001d\u0010z\u001a\u00020v8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bw\u0010m\u001a\u0004\bx\u0010yR\u0018\u0010{\u001a\u0004\u0018\u00010\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b{\u0010uR\"\u0010|\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b|\u0010}\u001a\u0004\b~\u0010C\"\u0004\b\u007f\u0010 R&\u0010\u0080\u0001\u001a\u00020<8\u0006@\u0006X\u0086\u000e¢\u0006\u0015\n\u0005\b\u0080\u0001\u0010h\u001a\u0005\b\u0081\u0001\u0010M\"\u0005\b\u0082\u0001\u0010]R)\u0010\u0083\u0001\u001a\u0004\u0018\u00010\f8\u0006@\u0006X\u0086\u000e¢\u0006\u0016\n\u0005\b\u0083\u0001\u0010u\u001a\u0005\b\u0084\u0001\u0010-\"\u0006\b\u0085\u0001\u0010\u0086\u0001R)\u0010\u0087\u0001\u001a\u00020N8\u0006@\u0006X\u0086.¢\u0006\u0018\n\u0006\b\u0087\u0001\u0010\u0088\u0001\u001a\u0006\b\u0089\u0001\u0010\u008a\u0001\"\u0006\b\u008b\u0001\u0010\u008c\u0001R\u0018\u0010\u008d\u0001\u001a\u00020<8\u0002@\u0002X\u0082\u000e¢\u0006\u0007\n\u0005\b\u008d\u0001\u0010hR.\u0010\u0092\u0001\u001a\u000f\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\f0\u008e\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u008f\u0001\u0010m\u001a\u0006\b\u0090\u0001\u0010\u0091\u0001R\"\u0010\u0095\u0001\u001a\u0004\u0018\u00010\f8B@\u0002X\u0082\u0084\u0002¢\u0006\u000e\n\u0005\b\u0093\u0001\u0010m\u001a\u0005\b\u0094\u0001\u0010-R,\u0010\u0097\u0001\u001a\u0005\u0018\u00010\u0096\u00018\u0006@\u0006X\u0086\u000e¢\u0006\u0018\n\u0006\b\u0097\u0001\u0010\u0098\u0001\u001a\u0006\b\u0099\u0001\u0010\u009a\u0001\"\u0006\b\u009b\u0001\u0010\u009c\u0001R&\u0010\u009d\u0001\u001a\u00020<8\u0006@\u0006X\u0086\u000e¢\u0006\u0015\n\u0005\b\u009d\u0001\u0010h\u001a\u0005\b\u009e\u0001\u0010M\"\u0005\b\u009f\u0001\u0010]R \u0010¢\u0001\u001a\u00020<8B@\u0002X\u0082\u0084\u0002¢\u0006\u000e\n\u0005\b \u0001\u0010m\u001a\u0005\b¡\u0001\u0010MR,\u0010¤\u0001\u001a\u0005\u0018\u00010£\u00018\u0006@\u0006X\u0086\u000e¢\u0006\u0018\n\u0006\b¤\u0001\u0010¥\u0001\u001a\u0006\b¦\u0001\u0010§\u0001\"\u0006\b¨\u0001\u0010©\u0001R(\u0010®\u0001\u001a\t\u0012\u0004\u0012\u00020\f0ª\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b«\u0001\u0010m\u001a\u0006\b¬\u0001\u0010\u00ad\u0001R\u0018\u0010¯\u0001\u001a\u00020\u00048\u0002@\u0002X\u0082\u000e¢\u0006\u0007\n\u0005\b¯\u0001\u0010}R\u0018\u0010°\u0001\u001a\u00020\u00048\u0002@\u0002X\u0082\u000e¢\u0006\u0007\n\u0005\b°\u0001\u0010}R(\u0010³\u0001\u001a\t\u0012\u0004\u0012\u00020\f0ª\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b±\u0001\u0010m\u001a\u0006\b²\u0001\u0010\u00ad\u0001R\"\u0010¸\u0001\u001a\u00030´\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\bµ\u0001\u0010m\u001a\u0006\b¶\u0001\u0010·\u0001R\u001c\u0010º\u0001\u001a\u0005\u0018\u00010¹\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bº\u0001\u0010»\u0001¨\u0006¾\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "video", "", "isPreviewEnd", "", "priceDialog", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;Z)V", "", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$PlayLinksBean;", "links", "", "link_name", "initSpinner", "(Ljava/util/List;Ljava/lang/String;)V", "id", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "response", FindBean.status_success, "Ljava/lang/Exception;", "Lkotlin/Exception;", C1568e.f1949a, "error", "doLove", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "doZan", "hasLove", "updageCollectNum", "(Z)V", "updateLoveNum", "s", "isNumber", "(Ljava/lang/String;)Z", "love", "getShowLoveTxt", "(Ljava/lang/String;)Ljava/lang/String;", "getShowFavorTxt", "item", "doBuyVideo", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;)V", "getVariableUrl", "()Ljava/lang/String;", "getVariableId", "Lkotlin/Function2;", "isSuccess", "hideLoading", "loadMovie", "(Ljava/lang/String;Lkotlin/jvm/functions/Function2;)V", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "addHistory", "(Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "Landroid/view/View;", "getItemRootView", "()Landroid/view/View;", "resumePlay", "()V", "", "position", "Landroidx/recyclerview/widget/RecyclerView;", "rv", "scrollTo", "(ILandroidx/recyclerview/widget/RecyclerView;)V", "autoRefresh", "()Z", "videoId", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", VideoListActivity.KEY_PARAMS, "api", "refreshList", "(Ljava/lang/String;Ljava/util/HashMap;Ljava/lang/String;)V", "initViews", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;)V", "Lcom/jbzd/media/movecartoons/bean/event/EventVideoPlayProgress;", "eventVideoPlayProgress", "onEventPlaying", "(Lcom/jbzd/media/movecartoons/bean/event/EventVideoPlayProgress;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "playVideo", "(I)V", "onResume", "onPause", "onStop", "Lcom/jbzd/media/movecartoons/bean/event/EventLine;", NotificationCompat.CATEGORY_EVENT, "onMessageEvent", "(Lcom/jbzd/media/movecartoons/bean/event/EventLine;)V", "onStart", "onDestroy", "mSelectP", "I", "getMSelectP", "setMSelectP", "previous", "mRequestParams$delegate", "Lkotlin/Lazy;", "getMRequestParams", "()Ljava/util/HashMap;", "mRequestParams", "currentVideoPosition", "getCurrentVideoPosition", "setCurrentVideoPosition", "variableUrl", "Ljava/lang/String;", "com/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$tagAdapter$2$1", "tagAdapter$delegate", "getTagAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$tagAdapter$2$1;", "tagAdapter", "variableId", "tool_show", "Z", "getTool_show", "setTool_show", "preview_link_position", "getPreview_link_position", "setPreview_link_position", "category", "getCategory", "setCategory", "(Ljava/lang/String;)V", "mHelper", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "getMHelper", "()Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "setMHelper", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;)V", "mPosition", "Landroid/util/ArrayMap;", "videoPlayHeader$delegate", "getVideoPlayHeader", "()Landroid/util/ArrayMap;", "videoPlayHeader", "mInitId$delegate", "getMInitId", "mInitId", "Landroid/widget/FrameLayout;", "disableDialog", "Landroid/widget/FrameLayout;", "getDisableDialog", "()Landroid/widget/FrameLayout;", "setDisableDialog", "(Landroid/widget/FrameLayout;)V", "link_position", "getLink_position", "setLink_position", "mInitPage$delegate", "getMInitPage", "mInitPage", "Lcom/jbzd/media/movecartoons/view/video/ListPlayerView;", "currentPlayer", "Lcom/jbzd/media/movecartoons/view/video/ListPlayerView;", "getCurrentPlayer", "()Lcom/jbzd/media/movecartoons/view/video/ListPlayerView;", "setCurrentPlayer", "(Lcom/jbzd/media/movecartoons/view/video/ListPlayerView;)V", "Landroidx/lifecycle/MutableLiveData;", "linkName$delegate", "getLinkName", "()Landroidx/lifecycle/MutableLiveData;", "linkName", "hasAddHistory", "mIsBackFromVipCenter", "link$delegate", "getLink", "link", "com/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$spinnerAdapter$2$1", "spinnerAdapter$delegate", "getSpinnerAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$spinnerAdapter$2$1;", "spinnerAdapter", "Landroid/widget/PopupWindow;", "popWindow", "Landroid/widget/PopupWindow;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PlayListFragment extends BaseListFragment<VideoDetailBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_API = "service_api";

    @NotNull
    public static final String KEY_INIT_ID = "init_id";

    @NotNull
    public static final String KEY_REQUEST_PARAMS = "request_params";

    @NotNull
    public static final String KEY_SHOW_ONLY_ONE = "show_only_one";

    @Nullable
    private ListPlayerView currentPlayer;
    private int currentVideoPosition;

    @Nullable
    private FrameLayout disableDialog;
    private boolean hasAddHistory;
    private int link_position;
    public BaseViewHolder mHelper;
    private boolean mIsBackFromVipCenter;
    private int mPosition;
    private int mSelectP;

    @Nullable
    private PopupWindow popWindow;
    private int preview_link_position;
    private int previous;

    @Nullable
    private String variableId;

    @Nullable
    private String variableUrl;

    @Nullable
    private String category = "";

    /* renamed from: videoPlayHeader$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy videoPlayHeader = LazyKt__LazyJVMKt.lazy(new Function0<ArrayMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$videoPlayHeader$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayMap<String, String> invoke() {
            ArrayMap<String, String> arrayMap = new ArrayMap<>();
            MyApp myApp = MyApp.f9891f;
            arrayMap.put("referer", MyApp.m4185f().cdn_header);
            arrayMap.put("allowCrossProtocolRedirects", "true");
            return arrayMap;
        }
    });

    /* renamed from: mInitId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mInitId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$mInitId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = PlayListFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString(PlayListFragment.KEY_INIT_ID);
        }
    });

    /* renamed from: mRequestParams$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mRequestParams = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$mRequestParams$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            Bundle arguments = PlayListFragment.this.getArguments();
            HashMap<String, String> hashMap = (HashMap) (arguments == null ? null : arguments.getSerializable(PlayListFragment.KEY_REQUEST_PARAMS));
            return hashMap == null ? new HashMap<>() : hashMap;
        }
    });

    /* renamed from: mInitPage$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mInitPage = LazyKt__LazyJVMKt.lazy(new Function0<Integer>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$mInitPage$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Integer invoke() {
            return Integer.valueOf(invoke2());
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final int invoke2() {
            HashMap mRequestParams;
            String str;
            try {
                mRequestParams = PlayListFragment.this.getMRequestParams();
                String str2 = "1";
                if (mRequestParams != null && (str = (String) mRequestParams.get("page")) != null) {
                    str2 = str;
                }
                return Integer.parseInt(str2);
            } catch (Exception unused) {
                return 1;
            }
        }
    });

    /* renamed from: link$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy link = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$link$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: linkName$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy linkName = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$linkName$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: tagAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tagAdapter = LazyKt__LazyJVMKt.lazy(new PlayListFragment$tagAdapter$2(this));
    private boolean tool_show = true;

    /* renamed from: spinnerAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy spinnerAdapter = LazyKt__LazyJVMKt.lazy(new PlayListFragment$spinnerAdapter$2(this));

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\n\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0012\u0010\u0013JY\u0010\u000b\u001a\u00020\n2\n\b\u0002\u0010\u0003\u001a\u0004\u0018\u00010\u00022(\b\u0002\u0010\u0006\u001a\"\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u0004j\u0010\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0018\u0001`\u00052\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u00022\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\u000b\u0010\fR\u0016\u0010\r\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\r\u0010\u000eR\u0016\u0010\u000f\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000f\u0010\u000eR\u0016\u0010\u0010\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0010\u0010\u000eR\u0016\u0010\u0011\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0011\u0010\u000e¨\u0006\u0014"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$Companion;", "", "", "id", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", VideoListActivity.KEY_PARAMS, "api", "", "isShowOnlyOne", "Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment;", "newInstance", "(Ljava/lang/String;Ljava/util/HashMap;Ljava/lang/String;Z)Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment;", "KEY_API", "Ljava/lang/String;", "KEY_INIT_ID", "KEY_REQUEST_PARAMS", "KEY_SHOW_ONLY_ONE", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ PlayListFragment newInstance$default(Companion companion, String str, HashMap hashMap, String str2, boolean z, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                str = null;
            }
            if ((i2 & 2) != 0) {
                hashMap = null;
            }
            if ((i2 & 4) != 0) {
                str2 = null;
            }
            if ((i2 & 8) != 0) {
                z = false;
            }
            return companion.newInstance(str, hashMap, str2, z);
        }

        @NotNull
        public final PlayListFragment newInstance(@Nullable String id, @Nullable HashMap<String, String> params, @Nullable String api, boolean isShowOnlyOne) {
            PlayListFragment playListFragment = new PlayListFragment();
            Bundle bundle = new Bundle();
            bundle.putString(PlayListFragment.KEY_INIT_ID, id);
            bundle.putSerializable(PlayListFragment.KEY_REQUEST_PARAMS, params);
            bundle.putString(PlayListFragment.KEY_API, api);
            bundle.putBoolean(PlayListFragment.KEY_SHOW_ONLY_ONE, isShowOnlyOne);
            Unit unit = Unit.INSTANCE;
            playListFragment.setArguments(bundle);
            return playListFragment;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void addHistory(VideoItemBean video) {
        if (video.curPlayDuration / 1000 <= 10) {
            return;
        }
        HashMap hashMap = new HashMap();
        String str = video.f10000id;
        if (str == null) {
            str = "";
        }
        hashMap.put("id", str);
        hashMap.put("type", video.getBasicType());
        hashMap.put("time", String.valueOf(video.curPlayDuration / 1000));
        C0917a.m221e(C0917a.f372a, "movie/doHistory", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$addHistory$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str2) {
                invoke2(str2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str2) {
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$addHistory$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 416);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindItem$lambda-6$lambda-3$lambda-1, reason: not valid java name */
    public static final void m5847bindItem$lambda6$lambda3$lambda1(VideoDetailBean item, int i2, int i3, int i4, int i5) {
        Intrinsics.checkNotNullParameter(item, "$item");
        item.curPlayDuration = i4;
        C4909c.m5569b().m5574g(new EventVideoPlayProgress(i2, i3, i4, i5, item));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindItem$lambda-6$lambda-3$lambda-2, reason: not valid java name */
    public static final void m5848bindItem$lambda6$lambda3$lambda2(VideoDetailBean item, PlayListFragment this$0) {
        Intrinsics.checkNotNullParameter(item, "$item");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (Intrinsics.areEqual(item.play_error_type, "none")) {
            return;
        }
        this$0.priceDialog(item, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void doBuyVideo(final VideoDetailBean item) {
        MovieDetailsActivity.INSTANCE.checkMoneyForBuyVideo(item, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$doBuyVideo$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                invoke(bool.booleanValue());
                return Unit.INSTANCE;
            }

            public final void invoke(boolean z) {
                if (z) {
                    HomeDataHelper homeDataHelper = HomeDataHelper.INSTANCE;
                    final VideoDetailBean videoDetailBean = VideoDetailBean.this;
                    String str = videoDetailBean.f10000id;
                    final PlayListFragment playListFragment = this;
                    homeDataHelper.doBuyMovie(str, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$doBuyVideo$1.1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                            invoke(bool.booleanValue());
                            return Unit.INSTANCE;
                        }

                        public final void invoke(boolean z2) {
                            PlayListFragment.this.variableId = videoDetailBean.f10000id;
                            PlayListFragment playListFragment2 = PlayListFragment.this;
                            String str2 = videoDetailBean.f10000id;
                            Intrinsics.checkNotNullExpressionValue(str2, "item.id");
                            final PlayListFragment playListFragment3 = PlayListFragment.this;
                            playListFragment2.loadMovie(str2, new Function2<Boolean, VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment.doBuyVideo.1.1.1
                                {
                                    super(2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool, VideoDetailBean videoDetailBean2) {
                                    invoke2(bool, videoDetailBean2);
                                    return Unit.INSTANCE;
                                }

                                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                                public final void invoke2(@Nullable Boolean bool, @Nullable VideoDetailBean videoDetailBean2) {
                                    if (videoDetailBean2 != null) {
                                        PlayListFragment.this.getAdapter().getData().set(PlayListFragment.this.getCurrentVideoPosition(), videoDetailBean2);
                                        Intrinsics.checkNotNullParameter("default_line", "key");
                                        Intrinsics.checkNotNullParameter("", "default");
                                        ApplicationC2828a applicationC2828a = C2827a.f7670a;
                                        if (applicationC2828a == null) {
                                            Intrinsics.throwUninitializedPropertyAccessException("context");
                                            throw null;
                                        }
                                        int i2 = 0;
                                        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
                                        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                                        Intrinsics.checkNotNull(sharedPreferences.getString("default_line", ""));
                                        if (PlayListFragment.this.getAdapter().getData().get(PlayListFragment.this.getCurrentVideoPosition()).play_links != null) {
                                            Intrinsics.checkNotNullParameter("default_line", "key");
                                            Intrinsics.checkNotNullParameter("", "default");
                                            ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
                                            if (applicationC2828a2 == null) {
                                                Intrinsics.throwUninitializedPropertyAccessException("context");
                                                throw null;
                                            }
                                            SharedPreferences sharedPreferences2 = applicationC2828a2.getSharedPreferences("default_storage", 0);
                                            Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                                            String string = sharedPreferences2.getString("default_line", "");
                                            Intrinsics.checkNotNull(string);
                                            if (Intrinsics.areEqual(PlayListFragment.this.getAdapter().getData().get(PlayListFragment.this.getCurrentVideoPosition()).play_error_type, "none")) {
                                                if (Intrinsics.areEqual(string, "")) {
                                                    PlayListFragment.this.getLink().setValue(PlayListFragment.this.getAdapter().getData().get(PlayListFragment.this.getCurrentVideoPosition()).play_links.get(0).m3u8_url);
                                                    PlayListFragment.this.getLinkName().setValue(PlayListFragment.this.getAdapter().getData().get(PlayListFragment.this.getCurrentVideoPosition()).play_links.get(0).name);
                                                } else {
                                                    List<VideoDetailBean.PlayLinksBean> list = PlayListFragment.this.getAdapter().getData().get(PlayListFragment.this.getCurrentVideoPosition()).play_links;
                                                    Intrinsics.checkNotNullExpressionValue(list, "adapter.data[currentVideoPosition].play_links");
                                                    PlayListFragment playListFragment4 = PlayListFragment.this;
                                                    for (Object obj : list) {
                                                        int i3 = i2 + 1;
                                                        if (i2 < 0) {
                                                            CollectionsKt__CollectionsKt.throwIndexOverflow();
                                                        }
                                                        if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj).f9995id, string)) {
                                                            playListFragment4.getLink().setValue(playListFragment4.getAdapter().getData().get(playListFragment4.getCurrentVideoPosition()).play_links.get(i2).m3u8_url);
                                                            playListFragment4.getLinkName().setValue(playListFragment4.getAdapter().getData().get(playListFragment4.getCurrentVideoPosition()).play_links.get(i2).name);
                                                        }
                                                        i2 = i3;
                                                    }
                                                }
                                            } else if (Intrinsics.areEqual(string, "")) {
                                                PlayListFragment.this.getLink().setValue(PlayListFragment.this.getAdapter().getData().get(PlayListFragment.this.getCurrentVideoPosition()).play_links.get(0).preview_m3u8_url);
                                                PlayListFragment.this.getLinkName().setValue(PlayListFragment.this.getAdapter().getData().get(PlayListFragment.this.getCurrentVideoPosition()).play_links.get(0).name);
                                            } else {
                                                List<VideoDetailBean.PlayLinksBean> list2 = PlayListFragment.this.getAdapter().getData().get(PlayListFragment.this.getCurrentVideoPosition()).play_links;
                                                Intrinsics.checkNotNullExpressionValue(list2, "adapter.data[currentVideoPosition].play_links");
                                                PlayListFragment playListFragment5 = PlayListFragment.this;
                                                for (Object obj2 : list2) {
                                                    int i4 = i2 + 1;
                                                    if (i2 < 0) {
                                                        CollectionsKt__CollectionsKt.throwIndexOverflow();
                                                    }
                                                    if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj2).f9995id, string)) {
                                                        playListFragment5.getLink().setValue(playListFragment5.getAdapter().getData().get(playListFragment5.getCurrentVideoPosition()).play_links.get(i2).preview_m3u8_url);
                                                        playListFragment5.getLinkName().setValue(playListFragment5.getAdapter().getData().get(playListFragment5.getCurrentVideoPosition()).play_links.get(i2).name);
                                                    }
                                                    i2 = i4;
                                                }
                                            }
                                            PlayListFragment.this.getAdapter().notifyDataSetChanged();
                                            C4909c.m5569b().m5574g(new EventLine(PlayListFragment.this.getLinkName().getValue(), PlayListFragment.this.getLink().getValue()));
                                        }
                                    }
                                }
                            });
                        }
                    });
                    return;
                }
                C2354n.m2449Z("余额不足请充值");
                RechargeActivity.Companion companion = RechargeActivity.INSTANCE;
                Context requireContext = this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void doLove(String id, Function1<Object, Unit> success, Function1<? super Exception, Unit> error) {
        HomeDataHelper.INSTANCE.doLove(id, "1", "", success, error);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doLove$default(PlayListFragment playListFragment, String str, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$doLove$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$doLove$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        playListFragment.doLove(str, function1, function12);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void doZan(String id, Function1<Object, Unit> success, Function1<? super Exception, Unit> error) {
        HomeDataHelper.INSTANCE.doZan(id, "", success, error);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doZan$default(PlayListFragment playListFragment, String str, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$doZan$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$doZan$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        playListFragment.doZan(str, function1, function12);
    }

    private final View getItemRootView() {
        return getRv_content().getChildAt(0);
    }

    private final String getMInitId() {
        return (String) this.mInitId.getValue();
    }

    private final int getMInitPage() {
        return ((Number) this.mInitPage.getValue()).intValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final HashMap<String, String> getMRequestParams() {
        return (HashMap) this.mRequestParams.getValue();
    }

    private final String getShowFavorTxt(String love) {
        return ((love == null || StringsKt__StringsJVMKt.isBlank(love)) || TextUtils.equals("0", love)) ? "收藏" : C0843e0.m182a(love);
    }

    private final String getShowLoveTxt(String love) {
        return ((love == null || StringsKt__StringsJVMKt.isBlank(love)) || TextUtils.equals("0", love)) ? "点赞" : C0843e0.m182a(love);
    }

    private final PlayListFragment$spinnerAdapter$2.C37851 getSpinnerAdapter() {
        return (PlayListFragment$spinnerAdapter$2.C37851) this.spinnerAdapter.getValue();
    }

    private final PlayListFragment$tagAdapter$2.C37861 getTagAdapter() {
        return (PlayListFragment$tagAdapter$2.C37861) this.tagAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getVariableId() {
        String str = this.variableId;
        return str == null ? getMInitId() : str;
    }

    private final String getVariableUrl() {
        String str = this.variableUrl;
        return str == null ? "movie/detail" : str;
    }

    private final ArrayMap<String, String> getVideoPlayHeader() {
        return (ArrayMap) this.videoPlayHeader.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    @SuppressLint({"ClickableViewAccessibility", "UseCompatLoadingForDrawables"})
    public final void initSpinner(List<? extends VideoDetailBean.PlayLinksBean> links, String link_name) {
        View inflate = LayoutInflater.from(requireContext()).inflate(R.layout.item_pop, (ViewGroup) null, false);
        Intrinsics.checkNotNullExpressionValue(inflate, "from(requireContext()).inflate(R.layout.item_pop, null, false)");
        RecyclerView recyclerView = (RecyclerView) inflate.findViewById(R.id.rv_spinner);
        C2354n.m2377B((TextView) inflate.findViewById(R.id.tv_cancel_chooseline), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$initSpinner$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView) {
                PopupWindow popupWindow;
                popupWindow = PlayListFragment.this.popWindow;
                if (popupWindow == null) {
                    return;
                }
                popupWindow.dismiss();
            }
        }, 1);
        setMItemDecoration(getItemDecoration());
        IntRange indices = CollectionsKt__CollectionsKt.getIndices(links);
        Intrinsics.checkNotNull(indices);
        int first = indices.getFirst();
        int last = indices.getLast();
        if (first <= last) {
            while (true) {
                int i2 = first + 1;
                if (Intrinsics.areEqual(link_name, links.get(first).name)) {
                    setMSelectP(first);
                }
                if (first == last) {
                    break;
                } else {
                    first = i2;
                }
            }
        }
        getSpinnerAdapter().setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) links));
        recyclerView.setLayoutManager(new LinearLayoutManager(requireActivity(), 1, false));
        recyclerView.setAdapter(getSpinnerAdapter());
        if (getMItemDecoration() != null) {
            RecyclerView.ItemDecoration mItemDecoration = getMItemDecoration();
            Intrinsics.checkNotNull(mItemDecoration);
            recyclerView.addItemDecoration(mItemDecoration);
        }
        PopupWindow popupWindow = new PopupWindow(inflate, -1, -1, true);
        this.popWindow = popupWindow;
        if (popupWindow != null) {
            popupWindow.setAnimationStyle(R.anim.push_bottom_in);
            popupWindow.setTouchable(true);
            popupWindow.setTouchInterceptor(new View.OnTouchListener() { // from class: b.a.a.a.t.g.m.a.c
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view, MotionEvent motionEvent) {
                    boolean m5850initSpinner$lambda9$lambda8;
                    m5850initSpinner$lambda9$lambda8 = PlayListFragment.m5850initSpinner$lambda9$lambda8(view, motionEvent);
                    return m5850initSpinner$lambda9$lambda8;
                }
            });
            popupWindow.setBackgroundDrawable(getResources().getDrawable(R.color.transparent_nearn));
            View view = getView();
            popupWindow.showAsDropDown(view != null ? view.findViewById(R$id.tv_spinner_short) : null, 0, 10);
        }
        new Handler().postDelayed(new Runnable() { // from class: b.a.a.a.t.g.m.a.d
            @Override // java.lang.Runnable
            public final void run() {
                PlayListFragment.m5849initSpinner$lambda10(PlayListFragment.this);
            }
        }, 1500L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initSpinner$lambda-10, reason: not valid java name */
    public static final void m5849initSpinner$lambda10(PlayListFragment this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        PopupWindow popupWindow = this$0.popWindow;
        Intrinsics.checkNotNull(popupWindow);
        if (popupWindow.isShowing()) {
            PopupWindow popupWindow2 = this$0.popWindow;
            Intrinsics.checkNotNull(popupWindow2);
            popupWindow2.dismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initSpinner$lambda-9$lambda-8, reason: not valid java name */
    public static final boolean m5850initSpinner$lambda9$lambda8(View view, MotionEvent motionEvent) {
        return false;
    }

    private final boolean isNumber(String s) {
        return StringsKt__StringNumberConversionsKt.toIntOrNull(s) != null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void loadMovie(String id, final Function2<? super Boolean, ? super VideoDetailBean, Unit> hideLoading) {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/detail", VideoDetailBean.class, hashMap, new Function1<VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$loadMovie$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(VideoDetailBean videoDetailBean) {
                invoke2(videoDetailBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable VideoDetailBean videoDetailBean) {
                hideLoading.invoke(Boolean.TRUE, videoDetailBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$loadMovie$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                hideLoading.invoke(Boolean.FALSE, null);
            }
        }, false, false, null, false, 480);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void loadMovie$default(PlayListFragment playListFragment, String str, Function2 function2, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function2 = new Function2<Boolean, VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$loadMovie$1
                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool, VideoDetailBean videoDetailBean) {
                    invoke2(bool, videoDetailBean);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Boolean bool, @Nullable VideoDetailBean videoDetailBean) {
                }
            };
        }
        playListFragment.loadMovie(str, function2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: playVideo$lambda-17$lambda-16$lambda-15, reason: not valid java name */
    public static final void m5851playVideo$lambda17$lambda16$lambda15(ListPlayerView this_run) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this_run.startPlayLogic();
    }

    private final void priceDialog(final VideoDetailBean video, boolean isPreviewEnd) {
        Object obj;
        String str = video.play_error;
        Intrinsics.checkNotNullExpressionValue(str, "video.play_error");
        String str2 = video.play_error_type;
        Intrinsics.checkNotNullExpressionValue(str2, "video.play_error_type");
        StringBuilder sb = new StringBuilder();
        sb.append("当前余额：");
        MyApp myApp = MyApp.f9891f;
        UserInfoBean userInfoBean = MyApp.f9892g;
        if (userInfoBean == null || (obj = userInfoBean.balance) == null) {
            obj = 0;
        }
        sb.append(obj);
        sb.append("金币");
        new UpgradePriceDialog(isPreviewEnd, "试看结束", str, str2, sb.toString(), Intrinsics.stringPlus(video.money, "金币解锁"), new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$priceDialog$1
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
                PlayListFragment.this.doBuyVideo(video);
            }
        }).show(getChildFragmentManager(), "vipDialog");
    }

    public static /* synthetic */ void refreshList$default(PlayListFragment playListFragment, String str, HashMap hashMap, String str2, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            str2 = null;
        }
        playListFragment.refreshList(str, hashMap, str2);
    }

    private final void resumePlay() {
        ListPlayerView listPlayerView;
        if (this.mIsBackFromVipCenter) {
            this.mIsBackFromVipCenter = false;
            request();
            return;
        }
        View itemRootView = getItemRootView();
        FrameLayout frameLayout = itemRootView == null ? null : (FrameLayout) itemRootView.findViewById(R.id.fl_dialog_disable);
        Integer valueOf = frameLayout != null ? Integer.valueOf(frameLayout.getVisibility()) : null;
        if ((valueOf != null && valueOf.intValue() == 0) || (listPlayerView = this.currentPlayer) == null) {
            return;
        }
        if (listPlayerView.getCurrentState() == 5) {
            listPlayerView.pauseToResume();
        } else {
            listPlayerView.startPlayLogic();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void scrollTo(int position, RecyclerView rv) {
        rv.scrollToPosition(position);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void updageCollectNum(boolean hasLove) {
        String obj;
        View view = getView();
        if (Intrinsics.areEqual(((ImageTextView) (view == null ? null : view.findViewById(R$id.itv_favorite))).getText().toString(), "收藏")) {
            obj = "0";
        } else {
            View view2 = getView();
            obj = ((ImageTextView) (view2 == null ? null : view2.findViewById(R$id.itv_favorite))).getText().toString();
        }
        if (isNumber(obj)) {
            if (hasLove) {
                View view3 = getView();
                ((ImageTextView) (view3 == null ? null : view3.findViewById(R$id.itv_favorite))).setText(String.valueOf(Integer.parseInt(obj) + 1));
            } else if (!hasLove) {
                View view4 = getView();
                ((ImageTextView) (view4 == null ? null : view4.findViewById(R$id.itv_favorite))).setText(String.valueOf(Integer.parseInt(obj) - 1));
            }
            View view5 = getView();
            if (!Intrinsics.areEqual(((ImageTextView) (view5 == null ? null : view5.findViewById(R$id.itv_favorite))).getText(), "0")) {
                View view6 = getView();
                if (!Intrinsics.areEqual(((ImageTextView) (view6 == null ? null : view6.findViewById(R$id.itv_favorite))).getText(), ChatMsgBean.SERVICE_ID)) {
                    return;
                }
            }
            View view7 = getView();
            ((ImageTextView) (view7 != null ? view7.findViewById(R$id.itv_favorite) : null)).setText("收藏");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void updateLoveNum(boolean hasLove) {
        String obj;
        View view = getView();
        if (Intrinsics.areEqual(((ImageTextView) (view == null ? null : view.findViewById(R$id.itv_favorite))).getText().toString(), "点赞")) {
            obj = "0";
        } else {
            View view2 = getView();
            obj = ((ImageTextView) (view2 == null ? null : view2.findViewById(R$id.itv_favorite))).getText().toString();
        }
        if (isNumber(obj)) {
            if (hasLove) {
                View view3 = getView();
                ((ImageTextView) (view3 == null ? null : view3.findViewById(R$id.itv_favorite))).setText(String.valueOf(Integer.parseInt(obj) + 1));
            } else if (!hasLove) {
                View view4 = getView();
                ((ImageTextView) (view4 == null ? null : view4.findViewById(R$id.itv_favorite))).setText(String.valueOf(Integer.parseInt(obj) - 1));
            }
            View view5 = getView();
            if (!Intrinsics.areEqual(((ImageTextView) (view5 == null ? null : view5.findViewById(R$id.itv_favorite))).getText(), "0")) {
                View view6 = getView();
                if (!Intrinsics.areEqual(((ImageTextView) (view6 == null ? null : view6.findViewById(R$id.itv_favorite))).getText(), ChatMsgBean.SERVICE_ID)) {
                    return;
                }
            }
            View view7 = getView();
            ((ImageTextView) (view7 != null ? view7.findViewById(R$id.itv_favorite) : null)).setText("点赞");
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean autoRefresh() {
        return false;
    }

    @Nullable
    public final String getCategory() {
        return this.category;
    }

    @Nullable
    public final ListPlayerView getCurrentPlayer() {
        return this.currentPlayer;
    }

    public final int getCurrentVideoPosition() {
        return this.currentVideoPosition;
    }

    @Nullable
    public final FrameLayout getDisableDialog() {
        return this.disableDialog;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_play_list;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        final FragmentActivity activity = getActivity();
        ViewPagerLayoutManager viewPagerLayoutManager = new ViewPagerLayoutManager(activity) { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$getLayoutManager$1
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean canScrollVertically() {
                return PlayListFragment.this.getAdapter().getData().size() > 1;
            }
        };
        viewPagerLayoutManager.setOnViewPagerListener(new PlayListFragment$getLayoutManager$2$1(this));
        return viewPagerLayoutManager;
    }

    @NotNull
    public final MutableLiveData<String> getLink() {
        return (MutableLiveData) this.link.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getLinkName() {
        return (MutableLiveData) this.linkName.getValue();
    }

    public final int getLink_position() {
        return this.link_position;
    }

    @NotNull
    public final BaseViewHolder getMHelper() {
        BaseViewHolder baseViewHolder = this.mHelper;
        if (baseViewHolder != null) {
            return baseViewHolder;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mHelper");
        throw null;
    }

    public final int getMSelectP() {
        return this.mSelectP;
    }

    public final int getPreview_link_position() {
        return this.preview_link_position;
    }

    public final boolean getTool_show() {
        return this.tool_show;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getVideo_list_container().setBackgroundColor(getResources().getColor(R.color.bgBlack));
        initRequestFrom(getMInitPage());
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        C4909c.m5569b().m5580m(this);
        ListPlayerView listPlayerView = this.currentPlayer;
        if (listPlayerView == null) {
            return;
        }
        listPlayerView.release();
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onEventPlaying(@NotNull EventVideoPlayProgress eventVideoPlayProgress) {
        Intrinsics.checkNotNullParameter(eventVideoPlayProgress, "eventVideoPlayProgress");
        View itemRootView = getItemRootView();
        TextView textView = itemRootView == null ? null : (TextView) itemRootView.findViewById(R.id.tv_curDuration);
        TextView textView2 = itemRootView == null ? null : (TextView) itemRootView.findViewById(R.id.tv_totalDuration);
        SeekBar seekBar = itemRootView != null ? (SeekBar) itemRootView.findViewById(R.id.progress_foreground) : null;
        if (itemRootView != null) {
        }
        if (textView != null) {
            textView.setText(CommonUtil.stringForTime(eventVideoPlayProgress.currentPosition));
        }
        if (textView2 != null) {
            textView2.setText(CommonUtil.stringForTime(eventVideoPlayProgress.duration));
        }
        if (seekBar != null) {
            seekBar.setMax(eventVideoPlayProgress.duration);
        }
        if (seekBar != null) {
            seekBar.setProgress(eventVideoPlayProgress.currentPosition);
        }
        if (eventVideoPlayProgress.currentPosition / 1000 > 10 && !this.hasAddHistory) {
            this.hasAddHistory = true;
            VideoItemBean videoItemBean = eventVideoPlayProgress.video;
            Intrinsics.checkNotNullExpressionValue(videoItemBean, "eventVideoPlayProgress.video");
            addHistory(videoItemBean);
        }
        if ((eventVideoPlayProgress.currentPosition % 1000) * 120 == 0) {
            VideoItemBean videoItemBean2 = eventVideoPlayProgress.video;
            Intrinsics.checkNotNullExpressionValue(videoItemBean2, "eventVideoPlayProgress.video");
            addHistory(videoItemBean2);
        }
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onMessageEvent(@Nullable EventLine event) {
        View itemRootView = getItemRootView();
        if (event != null) {
            ImageTextView imageTextView = itemRootView == null ? null : (ImageTextView) itemRootView.findViewById(R.id.tv_spinner_short);
            if (imageTextView != null) {
                imageTextView.setText(event.getLineName());
            }
            ListPlayerView listPlayerView = this.currentPlayer;
            if (listPlayerView != null) {
                String link = event.getLink();
                if (link == null) {
                    link = "";
                }
                listPlayerView.setUp(link, true, "");
            }
            ListPlayerView listPlayerView2 = this.currentPlayer;
            if (listPlayerView2 == null) {
                return;
            }
            listPlayerView2.startPlayLogic();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        ListPlayerView listPlayerView = this.currentPlayer;
        if (listPlayerView != null) {
            listPlayerView.playToPause();
        }
        C2920c.m3395d();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        resumePlay();
    }

    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        if (C4909c.m5569b().m5573f(this)) {
            return;
        }
        C4909c.m5569b().m5578k(this);
    }

    @Override // androidx.fragment.app.Fragment
    public void onStop() {
        super.onStop();
        try {
            addHistory(getAdapter().getData().get(this.mPosition));
        } catch (Exception unused) {
        }
    }

    public final void playVideo(final int position) {
        VideoDetailBean videoDetailBean;
        String str;
        this.currentVideoPosition = position;
        int i2 = 0;
        this.hasAddHistory = false;
        final View itemRootView = getItemRootView();
        try {
            videoDetailBean = getAdapter().getData().get(position);
        } catch (Exception unused) {
            videoDetailBean = null;
        }
        this.currentPlayer = itemRootView == null ? null : (ListPlayerView) itemRootView.findViewById(R.id.video_player);
        if ((videoDetailBean == null ? null : videoDetailBean.play_links) == null) {
            if (videoDetailBean == null || (str = videoDetailBean.f10000id) == null) {
                return;
            }
            loadMovie(str, new Function2<Boolean, VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$playVideo$2$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(2);
                }

                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool, VideoDetailBean videoDetailBean2) {
                    invoke2(bool, videoDetailBean2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Boolean bool, @Nullable VideoDetailBean videoDetailBean2) {
                    if (videoDetailBean2 != null) {
                        PlayListFragment.this.getAdapter().getData().set(position, videoDetailBean2);
                        Intrinsics.checkNotNullParameter("default_line", "key");
                        Intrinsics.checkNotNullParameter("", "default");
                        ApplicationC2828a applicationC2828a = C2827a.f7670a;
                        if (applicationC2828a == null) {
                            Intrinsics.throwUninitializedPropertyAccessException("context");
                            throw null;
                        }
                        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
                        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                        Intrinsics.checkNotNull(sharedPreferences.getString("default_line", ""));
                        if (PlayListFragment.this.getAdapter().getData().get(position).play_links != null) {
                            Intrinsics.checkNotNullParameter("default_line", "key");
                            Intrinsics.checkNotNullParameter("", "default");
                            ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
                            if (applicationC2828a2 == null) {
                                Intrinsics.throwUninitializedPropertyAccessException("context");
                                throw null;
                            }
                            SharedPreferences sharedPreferences2 = applicationC2828a2.getSharedPreferences("default_storage", 0);
                            Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                            String string = sharedPreferences2.getString("default_line", "");
                            Intrinsics.checkNotNull(string);
                            if (Intrinsics.areEqual(PlayListFragment.this.getAdapter().getData().get(position).play_error_type, "none")) {
                                if (Intrinsics.areEqual(string, "")) {
                                    PlayListFragment.this.getLink().setValue(PlayListFragment.this.getAdapter().getData().get(position).play_links.get(0).m3u8_url);
                                    PlayListFragment.this.getLinkName().setValue(PlayListFragment.this.getAdapter().getData().get(position).play_links.get(0).name);
                                } else {
                                    List<VideoDetailBean.PlayLinksBean> list = PlayListFragment.this.getAdapter().getData().get(position).play_links;
                                    Intrinsics.checkNotNullExpressionValue(list, "adapter.data[position].play_links");
                                    PlayListFragment playListFragment = PlayListFragment.this;
                                    int i3 = position;
                                    int i4 = 0;
                                    for (Object obj : list) {
                                        int i5 = i4 + 1;
                                        if (i4 < 0) {
                                            CollectionsKt__CollectionsKt.throwIndexOverflow();
                                        }
                                        if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj).f9995id, string)) {
                                            playListFragment.getLink().setValue(playListFragment.getAdapter().getData().get(i3).play_links.get(i4).m3u8_url);
                                            playListFragment.getLinkName().setValue(playListFragment.getAdapter().getData().get(i3).play_links.get(i4).name);
                                        }
                                        i4 = i5;
                                    }
                                }
                            } else if (Intrinsics.areEqual(string, "")) {
                                PlayListFragment.this.getLink().setValue(PlayListFragment.this.getAdapter().getData().get(position).play_links.get(0).preview_m3u8_url);
                                PlayListFragment.this.getLinkName().setValue(PlayListFragment.this.getAdapter().getData().get(position).play_links.get(0).name);
                            } else {
                                List<VideoDetailBean.PlayLinksBean> list2 = PlayListFragment.this.getAdapter().getData().get(position).play_links;
                                Intrinsics.checkNotNullExpressionValue(list2, "adapter.data[position].play_links");
                                PlayListFragment playListFragment2 = PlayListFragment.this;
                                int i6 = position;
                                int i7 = 0;
                                for (Object obj2 : list2) {
                                    int i8 = i7 + 1;
                                    if (i7 < 0) {
                                        CollectionsKt__CollectionsKt.throwIndexOverflow();
                                    }
                                    if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj2).f9995id, string)) {
                                        playListFragment2.getLink().setValue(playListFragment2.getAdapter().getData().get(i6).play_links.get(i7).preview_m3u8_url);
                                        playListFragment2.getLinkName().setValue(playListFragment2.getAdapter().getData().get(i6).play_links.get(i7).name);
                                    }
                                    i7 = i8;
                                }
                            }
                            PlayListFragment.this.getAdapter().notifyDataSetChanged();
                            C4909c.m5569b().m5574g(new EventLine(PlayListFragment.this.getLinkName().getValue(), PlayListFragment.this.getLink().getValue()));
                        }
                    }
                    if (!Intrinsics.areEqual(bool, Boolean.TRUE) || videoDetailBean2 == null) {
                        return;
                    }
                    View view = itemRootView;
                    TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_spinner_short);
                    if (textView != null) {
                        textView.setText(videoDetailBean2.play_links.get(0).name);
                    }
                    if (Intrinsics.areEqual(videoDetailBean2.video_user.is_follow, "y")) {
                        View view2 = itemRootView;
                        FollowTextView followTextView = view2 == null ? null : (FollowTextView) view2.findViewById(R.id.iv_userFollow);
                        if (followTextView != null) {
                            followTextView.setVisibility(8);
                        }
                        C2851b<Drawable> m3292f0 = C2354n.m2463c2(PlayListFragment.this).m3298p(videoDetailBean2.video_user.img).m3292f0();
                        View view3 = itemRootView;
                        ImageView imageView = view3 == null ? null : (ImageView) view3.findViewById(R.id.civ_head);
                        Objects.requireNonNull(imageView, "null cannot be cast to non-null type android.widget.ImageView");
                        m3292f0.m757R(imageView);
                    }
                    View view4 = itemRootView;
                    ImageTextView imageTextView = view4 == null ? null : (ImageTextView) view4.findViewById(R.id.tv_spinner_short);
                    if (imageTextView != null) {
                        imageTextView.setText(videoDetailBean2.play_links.get(0).name);
                    }
                    PlayListFragment playListFragment3 = PlayListFragment.this;
                    View view5 = itemRootView;
                    playListFragment3.setDisableDialog(view5 != null ? (FrameLayout) view5.findViewById(R.id.fl_dialog_disable) : null);
                    ListPlayerView currentPlayer = PlayListFragment.this.getCurrentPlayer();
                    if (currentPlayer == null) {
                        return;
                    }
                    PlayListFragment playListFragment4 = PlayListFragment.this;
                    if (videoDetailBean2.play_links != null) {
                        GSYBaseVideoPlayer currentPlayer2 = currentPlayer.getCurrentPlayer();
                        if (currentPlayer2 != null) {
                            String str2 = videoDetailBean2.play_links.get(0).m3u8_url;
                            if (str2 == null) {
                                str2 = "";
                            }
                            currentPlayer2.setUp(str2, true, "");
                        }
                        if (!Intrinsics.areEqual(videoDetailBean2.play_error_type, "none") && !videoDetailBean2.isPreviewOver) {
                            FrameLayout disableDialog = playListFragment4.getDisableDialog();
                            if (disableDialog == null) {
                                return;
                            }
                            disableDialog.setVisibility(0);
                            return;
                        }
                        FrameLayout disableDialog2 = playListFragment4.getDisableDialog();
                        if (disableDialog2 != null) {
                            disableDialog2.setVisibility(8);
                        }
                        GSYBaseVideoPlayer currentPlayer3 = currentPlayer.getCurrentPlayer();
                        if (currentPlayer3 != null) {
                            currentPlayer3.setVisibility(0);
                        }
                        currentPlayer.startPlayLogic();
                    }
                }
            });
            return;
        }
        setDisableDialog(itemRootView == null ? null : (FrameLayout) itemRootView.findViewById(R.id.fl_dialog_disable));
        final ListPlayerView currentPlayer = getCurrentPlayer();
        if (currentPlayer == null) {
            return;
        }
        FrameLayout disableDialog = getDisableDialog();
        if (disableDialog != null) {
            disableDialog.setVisibility(8);
        }
        String str2 = "key";
        Intrinsics.checkNotNullParameter("default_line", "key");
        Intrinsics.checkNotNullParameter("", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String string = sharedPreferences.getString("default_line", "");
        Intrinsics.checkNotNull(string);
        if (!Intrinsics.areEqual(string, "")) {
            List<VideoDetailBean.PlayLinksBean> list = videoDetailBean.play_links;
            Intrinsics.checkNotNullExpressionValue(list, "it.play_links");
            int i3 = 0;
            int i4 = 0;
            for (Object obj : list) {
                int i5 = i3 + 1;
                if (i3 < 0) {
                    CollectionsKt__CollectionsKt.throwIndexOverflow();
                }
                String str3 = ((VideoDetailBean.PlayLinksBean) obj).f9995id;
                Intrinsics.checkNotNullParameter("default_line", str2);
                Intrinsics.checkNotNullParameter("", "default");
                String str4 = str2;
                ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
                if (applicationC2828a2 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("context");
                    throw null;
                }
                SharedPreferences sharedPreferences2 = applicationC2828a2.getSharedPreferences("default_storage", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                String string2 = sharedPreferences2.getString("default_line", "");
                Intrinsics.checkNotNull(string2);
                if (Intrinsics.areEqual(str3, string2)) {
                    i4 = i3;
                }
                str2 = str4;
                i3 = i5;
            }
            i2 = i4;
        }
        ImageTextView imageTextView = itemRootView == null ? null : (ImageTextView) itemRootView.findViewById(R.id.tv_spinner_short);
        if (imageTextView != null) {
            imageTextView.setText(videoDetailBean.play_links.get(i2).name);
        }
        if (Intrinsics.areEqual(videoDetailBean.play_error_type, "none")) {
            GSYBaseVideoPlayer currentPlayer2 = currentPlayer.getCurrentPlayer();
            if (currentPlayer2 != null) {
                String str5 = videoDetailBean.play_links.get(i2).m3u8_url;
                if (str5 == null) {
                    str5 = "";
                }
                currentPlayer2.setUp(str5, true, "");
            }
        } else {
            GSYBaseVideoPlayer currentPlayer3 = currentPlayer.getCurrentPlayer();
            if (currentPlayer3 != null) {
                String str6 = videoDetailBean.play_links.get(i2).preview_m3u8_url;
                if (str6 == null) {
                    str6 = "";
                }
                currentPlayer3.setUp(str6, true, "");
            }
        }
        new Handler().postDelayed(new Runnable() { // from class: b.a.a.a.t.g.m.a.a
            @Override // java.lang.Runnable
            public final void run() {
                PlayListFragment.m5851playVideo$lambda17$lambda16$lambda15(ListPlayerView.this);
            }
        }, 500L);
    }

    public final void refreshList(@Nullable String videoId, @NotNull HashMap<String, String> params, @Nullable String api) {
        Intrinsics.checkNotNullParameter(params, "params");
        this.variableUrl = api;
        this.variableId = videoId;
        int i2 = 1;
        try {
            String str = params.get("page");
            if (str != null) {
                i2 = Integer.parseInt(str);
            }
        } catch (Exception unused) {
        }
        getMRequestParams().clear();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            getMRequestParams().put(entry.getKey(), entry.getValue());
        }
        BaseListFragment.initResetRequestFrom$default(this, i2, false, 2, null);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        HashMap<String, String> mRequestParams = getMRequestParams();
        String mInitId = getMInitId();
        Objects.requireNonNull(mInitId, "null cannot be cast to non-null type kotlin.String");
        mRequestParams.put("id", mInitId);
        return C0917a.m221e(C0917a.f372a, getVariableUrl(), VideoDetailBean.class, mRequestParams, new Function1<VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$request$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(VideoDetailBean videoDetailBean) {
                invoke2(videoDetailBean);
                return Unit.INSTANCE;
            }

            /* JADX WARN: Code restructure failed: missing block: B:14:0x0056, code lost:
            
                r8 = r1.getVariableId();
             */
            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final void invoke2(@org.jetbrains.annotations.Nullable com.jbzd.media.movecartoons.bean.response.VideoDetailBean r8) {
                /*
                    r7 = this;
                    kotlin.jvm.internal.Ref$BooleanRef r0 = new kotlin.jvm.internal.Ref$BooleanRef
                    r0.<init>()
                    com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment r1 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment.this
                    int r1 = r1.getCurrentPage()
                    com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment r2 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment.this
                    int r2 = r2.getFirstPage()
                    if (r1 != r2) goto L67
                    if (r8 != 0) goto L16
                    goto L67
                L16:
                    com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment r1 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment.this
                    java.util.List<com.jbzd.media.movecartoons.bean.response.VideoDetailBean> r2 = r8.relation_video
                    java.util.Iterator r2 = r2.iterator()
                    r3 = 0
                L1f:
                    boolean r4 = r2.hasNext()
                    if (r4 == 0) goto L52
                    int r4 = r3 + 1
                    java.lang.Object r5 = r2.next()
                    com.jbzd.media.movecartoons.bean.response.VideoDetailBean r5 = (com.jbzd.media.movecartoons.bean.response.VideoDetailBean) r5
                    java.lang.String r5 = r5.f10000id
                    java.lang.String r6 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment.access$getVariableId(r1)
                    boolean r5 = android.text.TextUtils.equals(r5, r6)
                    if (r5 == 0) goto L50
                    r2 = 1
                    r0.element = r2
                    com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment.access$setMPosition$p(r1, r3)
                    java.util.List<com.jbzd.media.movecartoons.bean.response.VideoDetailBean> r8 = r8.relation_video
                    r1.didRequestComplete(r8)
                    int r8 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment.access$getMPosition$p(r1)
                    androidx.recyclerview.widget.RecyclerView r2 = r1.getRv_content()
                    com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment.access$scrollTo(r1, r8, r2)
                    goto L52
                L50:
                    r3 = r4
                    goto L1f
                L52:
                    boolean r8 = r0.element
                    if (r8 != 0) goto L67
                    java.lang.String r8 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment.access$getVariableId(r1)
                    if (r8 != 0) goto L5d
                    goto L67
                L5d:
                    com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper r2 = com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper.INSTANCE
                    com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$request$1$1$1$1 r3 = new com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$request$1$1$1$1
                    r3.<init>()
                    r2.loadMovieDetail(r8, r3)
                L67:
                    return
                */
                throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment$request$1.invoke2(com.jbzd.media.movecartoons.bean.response.VideoDetailBean):void");
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$request$2
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
                PlayListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    public final void setCategory(@Nullable String str) {
        this.category = str;
    }

    public final void setCurrentPlayer(@Nullable ListPlayerView listPlayerView) {
        this.currentPlayer = listPlayerView;
    }

    public final void setCurrentVideoPosition(int i2) {
        this.currentVideoPosition = i2;
    }

    public final void setDisableDialog(@Nullable FrameLayout frameLayout) {
        this.disableDialog = frameLayout;
    }

    public final void setLink_position(int i2) {
        this.link_position = i2;
    }

    public final void setMHelper(@NotNull BaseViewHolder baseViewHolder) {
        Intrinsics.checkNotNullParameter(baseViewHolder, "<set-?>");
        this.mHelper = baseViewHolder;
    }

    public final void setMSelectP(int i2) {
        this.mSelectP = i2;
    }

    public final void setPreview_link_position(int i2) {
        this.preview_link_position = i2;
    }

    public final void setTool_show(boolean z) {
        this.tool_show = z;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull final BaseViewHolder helper, @NotNull final VideoDetailBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        this.tool_show = true;
        this.preview_link_position = 0;
        this.link_position = 0;
        setMHelper(helper);
        this.mSelectP = 0;
        TextView textView = (TextView) helper.m3912b(R.id.tv_buy);
        textView.setText(item.play_error);
        textView.setVisibility(Intrinsics.areEqual(item.play_error_type, "none") ? 8 : 0);
        C2354n.m2377B(textView, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Object obj;
                Intrinsics.checkNotNullParameter(it, "it");
                String str = PlayListFragment.this.getAdapter().getData().get(helper.getAdapterPosition()).play_error;
                Intrinsics.checkNotNullExpressionValue(str, "adapter.data[adapterPosition].play_error");
                String str2 = PlayListFragment.this.getAdapter().getData().get(helper.getAdapterPosition()).play_error_type;
                Intrinsics.checkNotNullExpressionValue(str2, "adapter.data[adapterPosition].play_error_type");
                StringBuilder sb = new StringBuilder();
                sb.append("当前余额：");
                MyApp myApp = MyApp.f9891f;
                UserInfoBean userInfoBean = MyApp.f9892g;
                if (userInfoBean == null || (obj = userInfoBean.balance) == null) {
                    obj = 0;
                }
                sb.append(obj);
                sb.append("金币");
                String sb2 = sb.toString();
                String stringPlus = Intrinsics.stringPlus(PlayListFragment.this.getAdapter().getData().get(helper.getAdapterPosition()).money, "金币解锁");
                final PlayListFragment playListFragment = PlayListFragment.this;
                final BaseViewHolder baseViewHolder = helper;
                new UpgradePriceDialog(false, "温馨提示", str, str2, sb2, stringPlus, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$1.1
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
                        PlayListFragment playListFragment2 = PlayListFragment.this;
                        playListFragment2.doBuyVideo(playListFragment2.getAdapter().getData().get(baseViewHolder.getAdapterPosition()));
                    }
                }).show(PlayListFragment.this.getChildFragmentManager(), "vipDialog");
            }
        }, 1);
        if (item.video_user != null) {
            C2354n.m2463c2(this).m3298p(item.video_user.img).m3292f0().m757R((ImageView) helper.m3912b(R.id.civ_head));
            if (Intrinsics.areEqual(item.video_user.is_follow, "y")) {
                helper.m3916f(R.id.iv_userFollow, true);
            } else {
                helper.m3916f(R.id.iv_userFollow, false);
            }
        }
        C2354n.m2377B(helper.m3912b(R.id.iv_userFollow), 0L, new Function1<FollowTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FollowTextView followTextView) {
                invoke2(followTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull FollowTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                boolean z = !PlayListFragment.this.getAdapter().getItem(helper.getAdapterPosition()).getHasFollow();
                helper.m3916f(R.id.iv_userFollow, z);
                item.is_follow = z ? "y" : "n";
                HashMap hashMap = new HashMap();
                String str = PlayListFragment.this.getAdapter().getItem(helper.getAdapterPosition()).video_user.f9997id;
                Intrinsics.checkNotNullExpressionValue(str, "adapter.getItem(adapterPosition).video_user.id");
                hashMap.put("id", str);
                C0917a c0917a = C0917a.f372a;
                C37781 c37781 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$2.1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                        C4909c.m5569b().m5574g(new EventSubscription());
                    }
                };
                final PlayListFragment playListFragment = PlayListFragment.this;
                final BaseViewHolder baseViewHolder = helper;
                final VideoDetailBean videoDetailBean = item;
                C0917a.m221e(c0917a, "user/doFollow", Object.class, hashMap, c37781, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$2.2
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                        boolean z2 = !PlayListFragment.this.getAdapter().getItem(baseViewHolder.getAdapterPosition()).getHasFollow();
                        baseViewHolder.m3916f(R.id.iv_userFollow, z2);
                        videoDetailBean.is_follow = z2 ? "y" : "n";
                    }
                }, false, false, null, false, 480);
            }
        }, 1);
        if (item.play_links != null) {
            ((ImageTextView) helper.m3912b(R.id.tv_spinner_short)).setText(item.play_links.get(0).name);
        }
        C2354n.m2377B(helper.m3912b(R.id.ll_mine_info), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull RelativeLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                UserPostHomeActivity.Companion companion = UserPostHomeActivity.Companion;
                Context requireContext = PlayListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str = PlayListFragment.this.getAdapter().getData().get(helper.getAdapterPosition()).video_user.f9997id;
                Intrinsics.checkNotNullExpressionValue(str, "adapter.data.get(adapterPosition).video_user.id");
                companion.start(requireContext, str);
            }
        }, 1);
        C2354n.m2377B(helper.m3912b(R.id.tv_showorhiden), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (PlayListFragment.this.getTool_show()) {
                    ((LinearLayout) helper.m3912b(R.id.ll_bottom_tool)).setVisibility(8);
                    ((LinearLayout) helper.m3912b(R.id.ll_bottom_content)).setVisibility(8);
                    View view = PlayListFragment.this.getView();
                    ((ImageTextView) (view != null ? view.findViewById(R$id.tv_showorhiden) : null)).setSelected(true);
                    PlayListFragment.this.setTool_show(false);
                    return;
                }
                ((LinearLayout) helper.m3912b(R.id.ll_bottom_tool)).setVisibility(0);
                ((LinearLayout) helper.m3912b(R.id.ll_bottom_content)).setVisibility(0);
                PlayListFragment.this.setTool_show(true);
                View view2 = PlayListFragment.this.getView();
                ((ImageTextView) (view2 != null ? view2.findViewById(R$id.tv_showorhiden) : null)).setSelected(false);
            }
        }, 1);
        final ImageTextView imageTextView = (ImageTextView) helper.m3912b(R.id.itv_favorite);
        imageTextView.setText(getShowFavorTxt(item.favorite));
        C2354n.m2377B(imageTextView, 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$5
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                PlayListFragment playListFragment = PlayListFragment.this;
                String str = item.f10000id;
                Intrinsics.checkNotNullExpressionValue(str, "item.id");
                final ImageTextView imageTextView2 = imageTextView;
                final PlayListFragment playListFragment2 = PlayListFragment.this;
                playListFragment.doLove(str, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$5.1
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
                    public final void invoke2(@Nullable Object obj) {
                        ImageTextView.this.setSelected(!r2.isSelected());
                        playListFragment2.updageCollectNum(ImageTextView.this.isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$5.2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
        final ImageTextView imageTextView2 = (ImageTextView) helper.m3912b(R.id.itv_love);
        imageTextView2.setText(getShowLoveTxt(item.love));
        C2354n.m2377B(imageTextView2, 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$6
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView3) {
                invoke2(imageTextView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ImageTextView.this.setSelected(!r5.isSelected());
                item.has_love = ImageTextView.this.isSelected() ? "y" : "n";
                PlayListFragment playListFragment = this;
                String str = item.f10000id;
                Intrinsics.checkNotNullExpressionValue(str, "item.id");
                final PlayListFragment playListFragment2 = this;
                final ImageTextView imageTextView3 = ImageTextView.this;
                playListFragment.doZan(str, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$6.1
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
                    public final void invoke2(@Nullable Object obj) {
                        PlayListFragment.this.updateLoveNum(imageTextView3.isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$6.2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
        setCurrentPlayer((ListPlayerView) helper.m3912b(R.id.video_player));
        helper.m3916f(R.id.ll_player, false);
        helper.m3916f(R.id.ll_videoMsg, false);
        SeekBar seekBar = (SeekBar) helper.m3912b(R.id.progress_foreground);
        seekBar.setProgress(0);
        seekBar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$7
            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onProgressChanged(@Nullable SeekBar seekBar2, int progress, boolean fromUser) {
                ListPlayerView currentPlayer = PlayListFragment.this.getCurrentPlayer();
                if (currentPlayer == null) {
                    return;
                }
                currentPlayer.seekTo(progress);
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStartTrackingTouch(@Nullable SeekBar seekBar2) {
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStopTrackingTouch(@Nullable SeekBar seekBar2) {
            }
        });
        final ImageView imageView = (ImageView) helper.m3912b(R.id.iv_video_fullscreen);
        imageView.setEnabled(false);
        final ListPlayerView currentPlayer = getCurrentPlayer();
        if (currentPlayer != null) {
            currentPlayer.setAutoFullWithSize(true);
            currentPlayer.setShowFullAnimation(true);
            currentPlayer.setLooping(false);
            String str = item.img_x;
            if (str == null) {
                str = "";
            }
            currentPlayer.loadCoverImageFitCenter(str);
            currentPlayer.setHideTopLayoutWhenSmall(Boolean.TRUE);
            if (item.getPlayLink() != null) {
                String playLink = item.getPlayLink();
                ArrayMap<String, String> videoPlayHeader = getVideoPlayHeader();
                String str2 = item.name;
                currentPlayer.setUp(playLink, true, (File) null, (Map<String, String>) videoPlayHeader, str2 == null ? "" : str2);
            }
            currentPlayer.setVideoAllCallBack(new MyVideoAllCallback() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$8$1
                @Override // com.jbzd.media.movecartoons.view.video.MyVideoAllCallback, p005b.p362y.p363a.p366f.InterfaceC2931g
                public void onPlayError(@Nullable String url, @NotNull Object... objects) {
                    List<VideoDetailBean.PlayLinksBean> list;
                    List<VideoDetailBean.PlayLinksBean> list2;
                    Intrinsics.checkNotNullParameter(objects, "objects");
                    VideoDetailBean videoDetailBean = PlayListFragment.this.getAdapter().getData().get(helper.getAdapterPosition());
                    if (Intrinsics.areEqual(videoDetailBean == null ? null : videoDetailBean.play_error_type, "none")) {
                        VideoDetailBean videoDetailBean2 = PlayListFragment.this.getAdapter().getData().get(helper.getAdapterPosition());
                        if (videoDetailBean2 != null && (list2 = videoDetailBean2.play_links) != null) {
                            PlayListFragment playListFragment = PlayListFragment.this;
                            BaseViewHolder baseViewHolder = helper;
                            int i2 = 0;
                            for (Object obj : list2) {
                                int i3 = i2 + 1;
                                if (i2 < 0) {
                                    CollectionsKt__CollectionsKt.throwIndexOverflow();
                                }
                                if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj).m3u8_url, url)) {
                                    if (i2 == 0) {
                                        MutableLiveData<String> link = playListFragment.getLink();
                                        VideoDetailBean videoDetailBean3 = playListFragment.getAdapter().getData().get(baseViewHolder.getAdapterPosition());
                                        List<VideoDetailBean.PlayLinksBean> list3 = videoDetailBean3 == null ? null : videoDetailBean3.play_links;
                                        Intrinsics.checkNotNull(list3);
                                        link.setValue(list3.get(1).m3u8_url);
                                        MutableLiveData<String> linkName = playListFragment.getLinkName();
                                        VideoDetailBean videoDetailBean4 = playListFragment.getAdapter().getData().get(baseViewHolder.getAdapterPosition());
                                        List<VideoDetailBean.PlayLinksBean> list4 = videoDetailBean4 == null ? null : videoDetailBean4.play_links;
                                        Intrinsics.checkNotNull(list4);
                                        linkName.setValue(list4.get(1).name);
                                    } else {
                                        MutableLiveData<String> link2 = playListFragment.getLink();
                                        VideoDetailBean videoDetailBean5 = playListFragment.getAdapter().getData().get(baseViewHolder.getAdapterPosition());
                                        List<VideoDetailBean.PlayLinksBean> list5 = videoDetailBean5 == null ? null : videoDetailBean5.play_links;
                                        Intrinsics.checkNotNull(list5);
                                        link2.setValue(list5.get(0).m3u8_url);
                                        MutableLiveData<String> linkName2 = playListFragment.getLinkName();
                                        VideoDetailBean videoDetailBean6 = playListFragment.getAdapter().getData().get(baseViewHolder.getAdapterPosition());
                                        List<VideoDetailBean.PlayLinksBean> list6 = videoDetailBean6 == null ? null : videoDetailBean6.play_links;
                                        Intrinsics.checkNotNull(list6);
                                        linkName2.setValue(list6.get(0).name);
                                    }
                                }
                                i2 = i3;
                            }
                        }
                    } else {
                        VideoDetailBean videoDetailBean7 = PlayListFragment.this.getAdapter().getData().get(helper.getAdapterPosition());
                        if (videoDetailBean7 != null && (list = videoDetailBean7.play_links) != null) {
                            PlayListFragment playListFragment2 = PlayListFragment.this;
                            BaseViewHolder baseViewHolder2 = helper;
                            int i4 = 0;
                            for (Object obj2 : list) {
                                int i5 = i4 + 1;
                                if (i4 < 0) {
                                    CollectionsKt__CollectionsKt.throwIndexOverflow();
                                }
                                if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj2).preview_m3u8_url, url)) {
                                    if (i4 == 0) {
                                        MutableLiveData<String> link3 = playListFragment2.getLink();
                                        VideoDetailBean videoDetailBean8 = playListFragment2.getAdapter().getData().get(baseViewHolder2.getAdapterPosition());
                                        List<VideoDetailBean.PlayLinksBean> list7 = videoDetailBean8 == null ? null : videoDetailBean8.play_links;
                                        Intrinsics.checkNotNull(list7);
                                        link3.setValue(list7.get(1).preview_m3u8_url);
                                        MutableLiveData<String> linkName3 = playListFragment2.getLinkName();
                                        VideoDetailBean videoDetailBean9 = playListFragment2.getAdapter().getData().get(baseViewHolder2.getAdapterPosition());
                                        List<VideoDetailBean.PlayLinksBean> list8 = videoDetailBean9 == null ? null : videoDetailBean9.play_links;
                                        Intrinsics.checkNotNull(list8);
                                        linkName3.setValue(list8.get(1).name);
                                    } else {
                                        MutableLiveData<String> link4 = playListFragment2.getLink();
                                        VideoDetailBean videoDetailBean10 = playListFragment2.getAdapter().getData().get(baseViewHolder2.getAdapterPosition());
                                        List<VideoDetailBean.PlayLinksBean> list9 = videoDetailBean10 == null ? null : videoDetailBean10.play_links;
                                        Intrinsics.checkNotNull(list9);
                                        link4.setValue(list9.get(0).preview_m3u8_url);
                                        MutableLiveData<String> linkName4 = playListFragment2.getLinkName();
                                        VideoDetailBean videoDetailBean11 = playListFragment2.getAdapter().getData().get(baseViewHolder2.getAdapterPosition());
                                        List<VideoDetailBean.PlayLinksBean> list10 = videoDetailBean11 == null ? null : videoDetailBean11.play_links;
                                        Intrinsics.checkNotNull(list10);
                                        linkName4.setValue(list10.get(0).name);
                                    }
                                }
                                i4 = i5;
                            }
                        }
                    }
                    C4909c.m5569b().m5574g(new EventLine(PlayListFragment.this.getLinkName().getValue(), PlayListFragment.this.getLink().getValue()));
                }

                @Override // com.jbzd.media.movecartoons.view.video.MyVideoAllCallback, p005b.p362y.p363a.p366f.InterfaceC2931g
                public void onPrepared(@Nullable String url, @NotNull Object... objects) {
                    Intrinsics.checkNotNullParameter(objects, "objects");
                    super.onPrepared(url, Arrays.copyOf(objects, objects.length));
                    imageView.setEnabled(true);
                }
            });
            currentPlayer.setGSYVideoProgressListener(new InterfaceC2927c() { // from class: b.a.a.a.t.g.m.a.b
                @Override // p005b.p362y.p363a.p366f.InterfaceC2927c
                /* renamed from: a */
                public final void mo301a(int i2, int i3, int i4, int i5) {
                    PlayListFragment.m5847bindItem$lambda6$lambda3$lambda1(VideoDetailBean.this, i2, i3, i4, i5);
                }
            });
            currentPlayer.setCallBack(new FullPlayerView.VideoCallBack() { // from class: b.a.a.a.t.g.m.a.f
                @Override // com.jbzd.media.movecartoons.view.video.FullPlayerView.VideoCallBack
                public final void onAutoComplete() {
                    PlayListFragment.m5848bindItem$lambda6$lambda3$lambda2(VideoDetailBean.this, this);
                }
            });
            C2354n.m2377B(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$8$4
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
                    ListPlayerView listPlayerView = ListPlayerView.this;
                    GSYBaseVideoPlayer startWindowFullscreen = listPlayerView.startWindowFullscreen(listPlayerView.getContext(), false, true);
                    Objects.requireNonNull(startWindowFullscreen, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.video.HomePlayerView");
                }
            }, 1);
        }
        TextView textView2 = (TextView) helper.m3912b(R.id.tv_username_upper);
        VideoDetailBean.UserBean userBean = item.user;
        if (userBean != null) {
            textView2.setText(userBean.nickname);
        } else {
            textView2.setText("");
        }
        ((TextView) helper.m3912b(R.id.etv_name)).setText(String.valueOf(item.name));
        RecyclerView recyclerView = (RecyclerView) helper.m3912b(R.id.rv_tag);
        PlayListFragment$tagAdapter$2.C37861 tagAdapter = getTagAdapter();
        List<TagBean> list = item.tags;
        tagAdapter.setNewData(list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
        recyclerView.setAdapter(getTagAdapter());
        FlexboxLayoutManager flexboxLayoutManager = new FlexboxLayoutManager(recyclerView.getContext());
        flexboxLayoutManager.m4176y(1);
        flexboxLayoutManager.m4175x(0);
        Unit unit = Unit.INSTANCE;
        recyclerView.setLayoutManager(flexboxLayoutManager);
        if (recyclerView.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(recyclerView.getContext());
            c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, recyclerView, 8.0d);
            c4053a.f10337e = C2354n.m2437V(recyclerView.getContext(), 3.0d);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            C1499a.m604Z(c4053a, recyclerView);
        }
        C2354n.m2377B(helper.m3912b(R.id.itv_download), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$10
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView3) {
                invoke2(imageTextView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C0917a c0917a = C0917a.f372a;
                HashMap hashMap = new HashMap();
                hashMap.put("id", VideoDetailBean.this.f10000id);
                Unit unit2 = Unit.INSTANCE;
                final VideoDetailBean videoDetailBean = VideoDetailBean.this;
                C0917a.m221e(c0917a, "movie/doDownload", DownloadVideoInfo.class, hashMap, new Function1<DownloadVideoInfo, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$10.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(DownloadVideoInfo downloadVideoInfo) {
                        invoke2(downloadVideoInfo);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable DownloadVideoInfo downloadVideoInfo) {
                        if (downloadVideoInfo == null) {
                            return;
                        }
                        downloadVideoInfo.f9947id = VideoDetailBean.this.f10000id;
                        Objects.requireNonNull(C0855k0.f257a);
                        C0855k0.f258b.m185a(downloadVideoInfo);
                        C2354n.m2409L1("缓存成功，请至离线缓存查看进度");
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$10.3
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                }, false, false, null, false, 480);
            }
        }, 1);
        C2354n.m2377B(helper.m3912b(R.id.itv_share), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$11
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView3) {
                invoke2(imageTextView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                InviteActivity.Companion companion = InviteActivity.INSTANCE;
                Context requireContext = PlayListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        C2354n.m2377B(helper.m3912b(R.id.tv_spinner_short), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$bindItem$1$12
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView3) {
                invoke2(imageTextView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PlayListFragment playListFragment = PlayListFragment.this;
                List<VideoDetailBean.PlayLinksBean> list2 = playListFragment.getAdapter().getData().get(helper.getAdapterPosition()).play_links;
                Intrinsics.checkNotNullExpressionValue(list2, "adapter.data[adapterPosition].play_links");
                View view = PlayListFragment.this.getView();
                playListFragment.initSpinner(list2, ((ImageTextView) (view == null ? null : view.findViewById(R$id.tv_spinner_short))).getText().toString());
            }
        }, 1);
    }
}

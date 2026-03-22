package com.jbzd.media.movecartoons.p396ui.post.topic;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.text.TextUtils;
import android.util.ArrayMap;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.core.widget.NestedScrollView;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.flexbox.FlexboxLayoutManager;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.CommentListBean;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import com.jbzd.media.movecartoons.bean.response.PostDetailBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.BuyDialog;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity;
import com.jbzd.media.movecartoons.p396ui.post.PostViewModel;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostDetailActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostDetailActivity$postCommentListAdapter$2;
import com.jbzd.media.movecartoons.p396ui.post.user.UserPostHomeActivity;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationV;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.Collection;
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
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.EnumC1570b;
import p005b.p143g.p144a.p147m.p150t.AbstractC1643k;
import p005b.p143g.p144a.p147m.p156v.p157c.C1704i;
import p005b.p143g.p144a.p147m.p156v.p157c.C1721z;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p005b.p362y.p363a.C2920c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Ç\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\b\u0012\n\u0002\u0018\u0002\n\u0002\b\u001c\n\u0002\u0018\u0002\n\u0002\b\u001e\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\b\u0016\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0016*\u0003lÅ\u0001\u0018\u0000 þ\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002þ\u0001B\b¢\u0006\u0005\bý\u0001\u0010\u0010J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0019\u0010\n\u001a\u00020\b2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\u0005H\u0014¢\u0006\u0004\b\u0011\u0010\u0010J\u000f\u0010\u0012\u001a\u00020\u0005H\u0014¢\u0006\u0004\b\u0012\u0010\u0010J%\u0010\u0018\u001a\u00020\u00052\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0015\u001a\u00020\b2\u0006\u0010\u0017\u001a\u00020\u0016¢\u0006\u0004\b\u0018\u0010\u0019J:\u0010 \u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u00032#\b\u0002\u0010\u001f\u001a\u001d\u0012\u0013\u0012\u00110\u001b¢\u0006\f\b\u001c\u0012\b\b\u001d\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\u00050\u001a¢\u0006\u0004\b \u0010!J\u000f\u0010\"\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\"\u0010\u0010J\u000f\u0010#\u001a\u00020\bH\u0016¢\u0006\u0004\b#\u0010$J\u000f\u0010%\u001a\u00020\bH\u0016¢\u0006\u0004\b%\u0010$J\r\u0010&\u001a\u00020\u0002¢\u0006\u0004\b&\u0010'R\u001d\u0010+\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010)\u001a\u0004\b*\u0010'R\u001d\u00100\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010)\u001a\u0004\b.\u0010/R\u001d\u00104\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b1\u0010)\u001a\u0004\b2\u00103R\u001d\u00109\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b6\u0010)\u001a\u0004\b7\u00108R\u001d\u0010<\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b:\u0010)\u001a\u0004\b;\u00108R\u001d\u0010A\u001a\u00020=8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b>\u0010)\u001a\u0004\b?\u0010@R\u001d\u0010F\u001a\u00020B8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bC\u0010)\u001a\u0004\bD\u0010ER\u001d\u0010I\u001a\u00020\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bG\u0010)\u001a\u0004\bH\u0010$R\u001d\u0010N\u001a\u00020J8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bK\u0010)\u001a\u0004\bL\u0010MR\u001d\u0010S\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bP\u0010)\u001a\u0004\bQ\u0010RR\u001d\u0010X\u001a\u00020T8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bU\u0010)\u001a\u0004\bV\u0010WR\u001d\u0010[\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bY\u0010)\u001a\u0004\bZ\u00103R\u001d\u0010`\u001a\u00020\\8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010)\u001a\u0004\b^\u0010_R\u001d\u0010e\u001a\u00020a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bb\u0010)\u001a\u0004\bc\u0010dR\u001d\u0010h\u001a\u00020=8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bf\u0010)\u001a\u0004\bg\u0010@R\u001d\u0010k\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bi\u0010)\u001a\u0004\bj\u00108R\u0016\u0010m\u001a\u00020l8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bm\u0010nR\u001d\u0010q\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bo\u0010)\u001a\u0004\bp\u00108R\u001d\u0010t\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\br\u0010)\u001a\u0004\bs\u00103R\u001d\u0010w\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bu\u0010)\u001a\u0004\bv\u0010/R\u001d\u0010z\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bx\u0010)\u001a\u0004\by\u00103R\u001d\u0010}\u001a\u00020a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b{\u0010)\u001a\u0004\b|\u0010dR \u0010\u0082\u0001\u001a\u00020~8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0004\b\u007f\u0010)\u001a\u0006\b\u0080\u0001\u0010\u0081\u0001R!\u0010\u0085\u0001\u001a\u00020~8F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0083\u0001\u0010)\u001a\u0006\b\u0084\u0001\u0010\u0081\u0001R \u0010\u0088\u0001\u001a\u00020=8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0086\u0001\u0010)\u001a\u0005\b\u0087\u0001\u0010@R!\u0010\u008b\u0001\u001a\u00020~8F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0089\u0001\u0010)\u001a\u0006\b\u008a\u0001\u0010\u0081\u0001R \u0010\u008e\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u008c\u0001\u0010)\u001a\u0005\b\u008d\u0001\u00103R \u0010\u0091\u0001\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u008f\u0001\u0010)\u001a\u0005\b\u0090\u0001\u0010/R \u0010\u0094\u0001\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0092\u0001\u0010)\u001a\u0005\b\u0093\u0001\u0010/R \u0010\u0097\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0095\u0001\u0010)\u001a\u0005\b\u0096\u0001\u00103R \u0010\u009a\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0098\u0001\u0010)\u001a\u0005\b\u0099\u0001\u00103R,\u0010\u009c\u0001\u001a\u0005\u0018\u00010\u009b\u00018\u0006@\u0006X\u0086\u000e¢\u0006\u0018\n\u0006\b\u009c\u0001\u0010\u009d\u0001\u001a\u0006\b\u009e\u0001\u0010\u009f\u0001\"\u0006\b \u0001\u0010¡\u0001R \u0010¤\u0001\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b¢\u0001\u0010)\u001a\u0005\b£\u0001\u0010/R \u0010§\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b¥\u0001\u0010)\u001a\u0005\b¦\u0001\u00103R \u0010ª\u0001\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b¨\u0001\u0010)\u001a\u0005\b©\u0001\u00108R \u0010\u00ad\u0001\u001a\u00020=8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b«\u0001\u0010)\u001a\u0005\b¬\u0001\u0010@R)\u0010®\u0001\u001a\u00020\u001b8\u0006@\u0006X\u0086\u000e¢\u0006\u0018\n\u0006\b®\u0001\u0010¯\u0001\u001a\u0006\b°\u0001\u0010±\u0001\"\u0006\b²\u0001\u0010³\u0001R \u0010¶\u0001\u001a\u00020a8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b´\u0001\u0010)\u001a\u0005\bµ\u0001\u0010dR \u0010¹\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b·\u0001\u0010)\u001a\u0005\b¸\u0001\u00103R\"\u0010¾\u0001\u001a\u00030º\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b»\u0001\u0010)\u001a\u0006\b¼\u0001\u0010½\u0001R \u0010Á\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b¿\u0001\u0010)\u001a\u0005\bÀ\u0001\u00103R \u0010Ä\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bÂ\u0001\u0010)\u001a\u0005\bÃ\u0001\u00103R\"\u0010É\u0001\u001a\u00030Å\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\bÆ\u0001\u0010)\u001a\u0006\bÇ\u0001\u0010È\u0001R \u0010Ì\u0001\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bÊ\u0001\u0010)\u001a\u0005\bË\u0001\u00108R!\u0010Ï\u0001\u001a\u00020~8F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\bÍ\u0001\u0010)\u001a\u0006\bÎ\u0001\u0010\u0081\u0001R \u0010Ò\u0001\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bÐ\u0001\u0010)\u001a\u0005\bÑ\u0001\u00108R \u0010Õ\u0001\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bÓ\u0001\u0010)\u001a\u0005\bÔ\u0001\u0010/R(\u0010Ö\u0001\u001a\u00020\f8\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\bÖ\u0001\u0010×\u0001\u001a\u0005\bØ\u0001\u0010\u000e\"\u0006\bÙ\u0001\u0010Ú\u0001R.\u0010ß\u0001\u001a\u000f\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\b0Û\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\bÜ\u0001\u0010)\u001a\u0006\bÝ\u0001\u0010Þ\u0001R \u0010â\u0001\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bà\u0001\u0010)\u001a\u0005\bá\u0001\u0010/R \u0010å\u0001\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bã\u0001\u0010)\u001a\u0005\bä\u0001\u00108R \u0010è\u0001\u001a\u00020=8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bæ\u0001\u0010)\u001a\u0005\bç\u0001\u0010@R\"\u0010í\u0001\u001a\u00030é\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\bê\u0001\u0010)\u001a\u0006\bë\u0001\u0010ì\u0001R \u0010ð\u0001\u001a\u00020=8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bî\u0001\u0010)\u001a\u0005\bï\u0001\u0010@R)\u0010ñ\u0001\u001a\u00020\u001b8\u0006@\u0006X\u0086\u000e¢\u0006\u0018\n\u0006\bñ\u0001\u0010¯\u0001\u001a\u0006\bò\u0001\u0010±\u0001\"\u0006\bó\u0001\u0010³\u0001R \u0010ö\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bô\u0001\u0010)\u001a\u0005\bõ\u0001\u00103R \u0010ù\u0001\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b÷\u0001\u0010)\u001a\u0005\bø\u0001\u00108R \u0010ü\u0001\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bú\u0001\u0010)\u001a\u0005\bû\u0001\u00103¨\u0006ÿ\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/topic/PostDetailActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/post/PostViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/PostDetailBean;", "postDetailBean", "", "noticeTips", "(Lcom/jbzd/media/movecartoons/bean/response/PostDetailBean;)V", "", "love", "getShowLoveTxt", "(Ljava/lang/String;)Ljava/lang/String;", "", "getLayoutId", "()I", "onBackPressed", "()V", "onPause", "onDestroy", "Landroid/content/Context;", "context", "url", "Landroid/widget/ImageView;", "target", "loadPreviewImage", "(Landroid/content/Context;Ljava/lang/String;Landroid/widget/ImageView;)V", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "isBalanceEnough", "result", "checkMoneyForBuyPost", "(Lcom/jbzd/media/movecartoons/bean/response/PostDetailBean;Lkotlin/jvm/functions/Function1;)V", "bindEvent", "getTopBarTitle", "()Ljava/lang/String;", "getRightTitle", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/post/PostViewModel;", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "Landroid/widget/LinearLayout;", "ll_posthome_usertop$delegate", "getLl_posthome_usertop", "()Landroid/widget/LinearLayout;", "ll_posthome_usertop", "im_postdetail_two_left_$delegate", "getIm_postdetail_two_left_", "()Landroid/widget/ImageView;", "im_postdetail_two_left_", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_postitem_click$delegate", "getItv_postitem_click", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_postitem_click", "itv_type_three_vip$delegate", "getItv_type_three_vip", "itv_type_three_vip", "Landroid/widget/TextView;", "tv_postdetail_comment$delegate", "getTv_postdetail_comment", "()Landroid/widget/TextView;", "tv_postdetail_comment", "Lcom/jbzd/media/movecartoons/view/FollowTextView;", "itv_postuser_follow$delegate", "getItv_postuser_follow", "()Lcom/jbzd/media/movecartoons/view/FollowTextView;", "itv_postuser_follow", "mPostId$delegate", "getMPostId", "mPostId", "Landroidx/core/widget/NestedScrollView;", "sroll_postdetail$delegate", "getSroll_postdetail", "()Landroidx/core/widget/NestedScrollView;", "sroll_postdetail", "Landroidx/appcompat/widget/AppCompatEditText;", "ed_input_comment$delegate", "getEd_input_comment", "()Landroidx/appcompat/widget/AppCompatEditText;", "ed_input_comment", "Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "iv_userfollow_avatar$delegate", "getIv_userfollow_avatar", "()Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "iv_userfollow_avatar", "iv_postitem_uper$delegate", "getIv_postitem_uper", "iv_postitem_uper", "Landroid/widget/RelativeLayout;", "ll_postitem_one$delegate", "getLl_postitem_one", "()Landroid/widget/RelativeLayout;", "ll_postitem_one", "Lcom/google/android/material/imageview/ShapeableImageView;", "iv_community_three_posthome$delegate", "getIv_community_three_posthome", "()Lcom/google/android/material/imageview/ShapeableImageView;", "iv_community_three_posthome", "tv_comment_loadstate$delegate", "getTv_comment_loadstate", "tv_comment_loadstate", "itv_confirm_post$delegate", "getItv_confirm_post", "itv_confirm_post", "com/jbzd/media/movecartoons/ui/post/topic/PostDetailActivity$fileAdapter$1", "fileAdapter", "Lcom/jbzd/media/movecartoons/ui/post/topic/PostDetailActivity$fileAdapter$1;", "iv_count_comment$delegate", "getIv_count_comment", "iv_count_comment", "im_community_img_single$delegate", "getIm_community_img_single", "im_community_img_single", "ll_share_postitem$delegate", "getLl_share_postitem", "ll_share_postitem", "im_postdetail_two_right_$delegate", "getIm_postdetail_two_right_", "im_postdetail_two_right_", "iv_community_img_twolft_posthome$delegate", "getIv_community_img_twolft_posthome", "iv_community_img_twolft_posthome", "Landroidx/recyclerview/widget/RecyclerView;", "rv_postdetail_files$delegate", "getRv_postdetail_files", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_postdetail_files", "rv_post_comments$delegate", "getRv_post_comments", "rv_post_comments", "tv_postdetail_nickname$delegate", "getTv_postdetail_nickname", "tv_postdetail_nickname", "rv_tag_post$delegate", "getRv_tag_post", "rv_tag_post", "back$delegate", "getBack", "back", "ll_postdetail_default$delegate", "getLl_postdetail_default", "ll_postdetail_default", "ll_postdetail_comment_loading$delegate", "getLl_postdetail_comment_loading", "ll_postdetail_comment_loading", "itv_type_one_money$delegate", "getItv_type_one_money", "itv_type_one_money", "itv_type_three_money$delegate", "getItv_type_three_money", "itv_type_three_money", "Lcom/jbzd/media/movecartoons/view/video/FullPlayerView;", "player_postdetail", "Lcom/jbzd/media/movecartoons/view/video/FullPlayerView;", "getPlayer_postdetail", "()Lcom/jbzd/media/movecartoons/view/video/FullPlayerView;", "setPlayer_postdetail", "(Lcom/jbzd/media/movecartoons/view/video/FullPlayerView;)V", "ll_community_img_three$delegate", "getLl_community_img_three", "ll_community_img_three", "iv_mypost_del$delegate", "getIv_mypost_del", "iv_mypost_del", "itv_postitem_likes$delegate", "getItv_postitem_likes", "itv_postitem_likes", "tv_ll_line_postitem$delegate", "getTv_ll_line_postitem", "tv_ll_line_postitem", "loadingMoreSuccess", "Z", "getLoadingMoreSuccess", "()Z", "setLoadingMoreSuccess", "(Z)V", "iv_community_two_posthome$delegate", "getIv_community_two_posthome", "iv_community_two_posthome", "iv_postitem_uservip$delegate", "getIv_postitem_uservip", "iv_postitem_uservip", "Landroid/widget/ProgressBar;", "progress_comment$delegate", "getProgress_comment", "()Landroid/widget/ProgressBar;", "progress_comment", "iv_postitem_pause$delegate", "getIv_postitem_pause", "iv_postitem_pause", "iv_postdetail_two_type$delegate", "getIv_postdetail_two_type", "iv_postdetail_two_type", "com/jbzd/media/movecartoons/ui/post/topic/PostDetailActivity$postCommentListAdapter$2$1", "postCommentListAdapter$delegate", "getPostCommentListAdapter", "()Lcom/jbzd/media/movecartoons/ui/post/topic/PostDetailActivity$postCommentListAdapter$2$1;", "postCommentListAdapter", "itv_type_two_vip$delegate", "getItv_type_two_vip", "itv_type_two_vip", "rv_tag_post_games$delegate", "getRv_tag_post_games", "rv_tag_post_games", "itv_type_one_vip$delegate", "getItv_type_one_vip", "itv_type_one_vip", "ll_mypost_time_del$delegate", "getLl_mypost_time_del", "ll_mypost_time_del", "pageComment", "I", "getPageComment", "setPageComment", "(I)V", "Landroid/util/ArrayMap;", "videoPlayHeader$delegate", "getVideoPlayHeader", "()Landroid/util/ArrayMap;", "videoPlayHeader", "ll_community_img_two$delegate", "getLl_community_img_two", "ll_community_img_two", "itv_favorite$delegate", "getItv_favorite", "itv_favorite", "tv_post_created_at$delegate", "getTv_post_created_at", "tv_post_created_at", "Landroidx/appcompat/widget/AppCompatTextView;", "tv_posthome_childitemtitle$delegate", "getTv_posthome_childitemtitle", "()Landroidx/appcompat/widget/AppCompatTextView;", "tv_posthome_childitemtitle", "tv_posthome_content$delegate", "getTv_posthome_content", "tv_posthome_content", "noMoreData", "getNoMoreData", "setNoMoreData", "iv_community_threevideo$delegate", "getIv_community_threevideo", "iv_community_threevideo", "ll_nodata_comment$delegate", "getLl_nodata_comment", "ll_nodata_comment", "itv_type_two_money$delegate", "getItv_type_two_money", "itv_type_two_money", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostDetailActivity extends MyThemeActivity<PostViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String postId = "postId";
    private boolean loadingMoreSuccess;
    private boolean noMoreData;

    @Nullable
    private FullPlayerView player_postdetail;
    private int pageComment = 1;

    /* renamed from: mPostId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$mPostId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            Intent intent = PostDetailActivity.this.getIntent();
            String stringExtra = intent == null ? null : intent.getStringExtra(PostDetailActivity.INSTANCE.getPostId());
            Objects.requireNonNull(stringExtra, "null cannot be cast to non-null type kotlin.String");
            return stringExtra;
        }
    });

    /* renamed from: videoPlayHeader$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy videoPlayHeader = LazyKt__LazyJVMKt.lazy(new Function0<ArrayMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$videoPlayHeader$2
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

    /* renamed from: back$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy back = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$back$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.back);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    @NotNull
    private final PostDetailActivity$fileAdapter$1 fileAdapter = new PostDetailActivity$fileAdapter$1(this);

    /* renamed from: itv_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_favorite = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.itv_favorite);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: ll_postdetail_default$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_postdetail_default = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_postdetail_default$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostDetailActivity.this.findViewById(R.id.ll_postdetail_default);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: rv_postdetail_files$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_postdetail_files = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$rv_postdetail_files$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) PostDetailActivity.this.findViewById(R.id.rv_postdetail_files);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: rv_tag_post_games$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_tag_post_games = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$rv_tag_post_games$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) PostDetailActivity.this.findViewById(R.id.rv_tag_post_games);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: rv_tag_post$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_tag_post = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$rv_tag_post$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) PostDetailActivity.this.findViewById(R.id.rv_tag_post);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: ll_posthome_usertop$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_posthome_usertop = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_posthome_usertop$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostDetailActivity.this.findViewById(R.id.ll_posthome_usertop);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: itv_postuser_follow$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_postuser_follow = LazyKt__LazyJVMKt.lazy(new Function0<FollowTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_postuser_follow$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FollowTextView invoke() {
            FollowTextView followTextView = (FollowTextView) PostDetailActivity.this.findViewById(R.id.itv_postuser_follow);
            Intrinsics.checkNotNull(followTextView);
            return followTextView;
        }
    });

    /* renamed from: ll_mypost_time_del$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_mypost_time_del = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_mypost_time_del$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostDetailActivity.this.findViewById(R.id.ll_mypost_time_del);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: iv_mypost_del$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_mypost_del = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_mypost_del$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.iv_mypost_del);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: iv_userfollow_avatar$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_userfollow_avatar = LazyKt__LazyJVMKt.lazy(new Function0<CircleImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_userfollow_avatar$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CircleImageView invoke() {
            CircleImageView circleImageView = (CircleImageView) PostDetailActivity.this.findViewById(R.id.iv_userfollow_avatar);
            Intrinsics.checkNotNull(circleImageView);
            return circleImageView;
        }
    });

    /* renamed from: iv_postitem_uper$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_postitem_uper = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_postitem_uper$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.iv_postitem_uper);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_postdetail_nickname$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_postdetail_nickname = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$tv_postdetail_nickname$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostDetailActivity.this.findViewById(R.id.tv_postdetail_nickname);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: iv_postitem_uservip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_postitem_uservip = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_postitem_uservip$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.iv_postitem_uservip);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_post_created_at$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_post_created_at = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$tv_post_created_at$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostDetailActivity.this.findViewById(R.id.tv_post_created_at);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_posthome_childitemtitle$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_posthome_childitemtitle = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$tv_posthome_childitemtitle$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatTextView invoke() {
            AppCompatTextView appCompatTextView = (AppCompatTextView) PostDetailActivity.this.findViewById(R.id.tv_posthome_childitemtitle);
            Intrinsics.checkNotNull(appCompatTextView);
            return appCompatTextView;
        }
    });

    /* renamed from: tv_posthome_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_posthome_content = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$tv_posthome_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostDetailActivity.this.findViewById(R.id.tv_posthome_content);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: ll_community_img_three$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_community_img_three = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_community_img_three$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostDetailActivity.this.findViewById(R.id.ll_community_img_three);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_community_img_two$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_community_img_two = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_community_img_two$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostDetailActivity.this.findViewById(R.id.ll_community_img_two);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_postitem_one$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_postitem_one = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_postitem_one$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) PostDetailActivity.this.findViewById(R.id.ll_postitem_one);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: iv_community_img_twolft_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_community_img_twolft_posthome = LazyKt__LazyJVMKt.lazy(new Function0<ShapeableImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_community_img_twolft_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ShapeableImageView invoke() {
            ShapeableImageView shapeableImageView = (ShapeableImageView) PostDetailActivity.this.findViewById(R.id.iv_community_img_twolft_posthome);
            Intrinsics.checkNotNull(shapeableImageView);
            return shapeableImageView;
        }
    });

    /* renamed from: iv_community_two_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_community_two_posthome = LazyKt__LazyJVMKt.lazy(new Function0<ShapeableImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_community_two_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ShapeableImageView invoke() {
            ShapeableImageView shapeableImageView = (ShapeableImageView) PostDetailActivity.this.findViewById(R.id.iv_community_two_posthome);
            Intrinsics.checkNotNull(shapeableImageView);
            return shapeableImageView;
        }
    });

    /* renamed from: iv_community_three_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_community_three_posthome = LazyKt__LazyJVMKt.lazy(new Function0<ShapeableImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_community_three_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ShapeableImageView invoke() {
            ShapeableImageView shapeableImageView = (ShapeableImageView) PostDetailActivity.this.findViewById(R.id.iv_community_three_posthome);
            Intrinsics.checkNotNull(shapeableImageView);
            return shapeableImageView;
        }
    });

    /* renamed from: iv_community_threevideo$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_community_threevideo = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_community_threevideo$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.iv_community_threevideo);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: itv_type_three_money$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_type_three_money = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_type_three_money$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.itv_type_three_money);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: itv_type_three_vip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_type_three_vip = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_type_three_vip$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.itv_type_three_vip);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: im_postdetail_two_left_$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy im_postdetail_two_left_ = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$im_postdetail_two_left_$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.im_postdetail_two_left_);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: im_postdetail_two_right_$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy im_postdetail_two_right_ = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$im_postdetail_two_right_$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.im_postdetail_two_right_);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: iv_postdetail_two_type$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_postdetail_two_type = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_postdetail_two_type$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.iv_postdetail_two_type);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: itv_type_two_money$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_type_two_money = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_type_two_money$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.itv_type_two_money);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: itv_type_two_vip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_type_two_vip = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_type_two_vip$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.itv_type_two_vip);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: im_community_img_single$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy im_community_img_single = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$im_community_img_single$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.im_community_img_single);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: iv_postitem_pause$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_postitem_pause = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_postitem_pause$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.iv_postitem_pause);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: itv_type_one_vip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_type_one_vip = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_type_one_vip$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.itv_type_one_vip);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_type_one_money$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_type_one_money = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_type_one_money$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostDetailActivity.this.findViewById(R.id.itv_type_one_money);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_ll_line_postitem$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_ll_line_postitem = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$tv_ll_line_postitem$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostDetailActivity.this.findViewById(R.id.tv_ll_line_postitem);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: itv_postitem_click$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_postitem_click = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_postitem_click$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.itv_postitem_click);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: iv_count_comment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_count_comment = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$iv_count_comment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.iv_count_comment);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_postitem_likes$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_postitem_likes = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_postitem_likes$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.itv_postitem_likes);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: ll_share_postitem$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_share_postitem = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_share_postitem$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostDetailActivity.this.findViewById(R.id.ll_share_postitem);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: rv_post_comments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_post_comments = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$rv_post_comments$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) PostDetailActivity.this.findViewById(R.id.rv_post_comments);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: ll_postdetail_comment_loading$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_postdetail_comment_loading = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_postdetail_comment_loading$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostDetailActivity.this.findViewById(R.id.ll_postdetail_comment_loading);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_nodata_comment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_nodata_comment = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ll_nodata_comment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.ll_nodata_comment);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: progress_comment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy progress_comment = LazyKt__LazyJVMKt.lazy(new Function0<ProgressBar>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$progress_comment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ProgressBar invoke() {
            ProgressBar progressBar = (ProgressBar) PostDetailActivity.this.findViewById(R.id.progress_comment);
            Intrinsics.checkNotNull(progressBar);
            return progressBar;
        }
    });

    /* renamed from: tv_comment_loadstate$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_comment_loadstate = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$tv_comment_loadstate$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostDetailActivity.this.findViewById(R.id.tv_comment_loadstate);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_postdetail_comment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_postdetail_comment = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$tv_postdetail_comment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostDetailActivity.this.findViewById(R.id.tv_postdetail_comment);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: sroll_postdetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sroll_postdetail = LazyKt__LazyJVMKt.lazy(new Function0<NestedScrollView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$sroll_postdetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final NestedScrollView invoke() {
            NestedScrollView nestedScrollView = (NestedScrollView) PostDetailActivity.this.findViewById(R.id.sroll_postdetail);
            Intrinsics.checkNotNull(nestedScrollView);
            return nestedScrollView;
        }
    });

    /* renamed from: itv_confirm_post$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_confirm_post = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$itv_confirm_post$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) PostDetailActivity.this.findViewById(R.id.itv_confirm_post);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: ed_input_comment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ed_input_comment = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$ed_input_comment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatEditText invoke() {
            AppCompatEditText appCompatEditText = (AppCompatEditText) PostDetailActivity.this.findViewById(R.id.ed_input_comment);
            Intrinsics.checkNotNull(appCompatEditText);
            return appCompatEditText;
        }
    });

    /* renamed from: postCommentListAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy postCommentListAdapter = LazyKt__LazyJVMKt.lazy(new Function0<PostDetailActivity$postCommentListAdapter$2.C38671>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$postCommentListAdapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        /* JADX WARN: Type inference failed for: r0v0, types: [com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$postCommentListAdapter$2$1] */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C38671 invoke() {
            final PostDetailActivity postDetailActivity = PostDetailActivity.this;
            return new BaseQuickAdapter<CommentListBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$postCommentListAdapter$2.1
                {
                    super(R.layout.item_post_comment, null, 2, null);
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull final BaseViewHolder helper, @NotNull final CommentListBean item) {
                    String showLoveTxt;
                    Resources resources;
                    int i2;
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    final PostDetailActivity postDetailActivity2 = PostDetailActivity.this;
                    C2852c m2467d2 = C2354n.m2467d2(postDetailActivity2);
                    String str = item.img;
                    if (str == null) {
                        str = "";
                    }
                    C1558h mo770c = m2467d2.mo770c();
                    mo770c.mo763X(str);
                    ((C2851b) mo770c).m3292f0().m757R((ImageView) helper.m3912b(R.id.iv_post_comment_userheder));
                    TextView textView = (TextView) helper.m3912b(R.id.tv_post_username);
                    TextView textView2 = (TextView) helper.m3912b(R.id.tv_post_comment_content);
                    TextView textView3 = (TextView) helper.m3912b(R.id.tv_post_comment_time);
                    ImageTextView imageTextView = (ImageTextView) helper.m3912b(R.id.itv_postcomment_likes);
                    TextView textView4 = (TextView) helper.m3912b(R.id.tv_post_comment_reply);
                    if (Intrinsics.areEqual(item.user_id, ChatMsgBean.SERVICE_ID)) {
                        imageTextView.setVisibility(8);
                        textView4.setVisibility(8);
                    } else {
                        imageTextView.setVisibility(0);
                        textView4.setVisibility(0);
                    }
                    textView.setText(item.nickname);
                    textView2.setText(item.content);
                    textView3.setText(item.label);
                    showLoveTxt = postDetailActivity2.getShowLoveTxt(item.love);
                    imageTextView.setText(showLoveTxt);
                    if (Intrinsics.areEqual(item.love, "0") && Intrinsics.areEqual(item.has_love, "y")) {
                        imageTextView.setText("已赞");
                    }
                    imageTextView.setSelected(Intrinsics.areEqual(item.has_love, "y"));
                    if (Intrinsics.areEqual(item.has_love, "y")) {
                        resources = postDetailActivity2.getResources();
                        i2 = R.color.color_ff0000;
                    } else {
                        resources = postDetailActivity2.getResources();
                        i2 = R.color.color_comment;
                    }
                    helper.m3920j(R.id.itv_postcomment_likes, resources.getColor(i2));
                    C2354n.m2374A(imageTextView, 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$postCommentListAdapter$2$1$convert$1$1
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
                            PostViewModel viewModel;
                            Intrinsics.checkNotNullParameter(it, "it");
                            getItem(helper.getPosition()).setHas_love(Intrinsics.areEqual(getItem(helper.getPosition()).has_love, "y") ? "n" : "y");
                            if (Intrinsics.areEqual(getItem(helper.getPosition()).has_love, "y")) {
                                CommentListBean item2 = getItem(helper.getPosition());
                                String str2 = getItem(helper.getPosition()).love;
                                Intrinsics.checkNotNullExpressionValue(str2, "getItem(position).love");
                                item2.love = String.valueOf(Integer.parseInt(str2) + 1);
                            } else {
                                CommentListBean item3 = getItem(helper.getPosition());
                                Intrinsics.checkNotNullExpressionValue(getItem(helper.getPosition()).love, "getItem(position).love");
                                item3.love = String.valueOf(Integer.parseInt(r1) - 1);
                            }
                            notifyItemChanged(helper.getPosition());
                            viewModel = postDetailActivity2.getViewModel();
                            String str3 = item.f9922id;
                            Intrinsics.checkNotNullExpressionValue(str3, "item.id");
                            final PostDetailActivity postDetailActivity3 = postDetailActivity2;
                            viewModel.commentDoLove(str3, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$postCommentListAdapter$2$1$convert$1$1.1
                                {
                                    super(1);
                                }

                                @Override // kotlin.jvm.functions.Function1
                                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                                    invoke(bool.booleanValue());
                                    return Unit.INSTANCE;
                                }

                                public final void invoke(boolean z) {
                                    PostDetailActivity.this.hideLoadingDialog();
                                }
                            });
                        }
                    }, 1);
                }
            };
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(PostViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$special$$inlined$viewModels$default$1
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

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\t\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000e¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/topic/PostDetailActivity$Companion;", "", "Landroid/content/Context;", "context", "", "post_Id", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "postId", "Ljava/lang/String;", "getPostId", "()Ljava/lang/String;", "setPostId", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getPostId() {
            return PostDetailActivity.postId;
        }

        public final void setPostId(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            PostDetailActivity.postId = str;
        }

        public final void start(@NotNull Context context, @NotNull String post_Id) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(post_Id, "post_Id");
            Intent intent = new Intent(context, (Class<?>) PostDetailActivity.class);
            intent.putExtra(PostDetailActivity.INSTANCE.getPostId(), post_Id);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-14$lambda-13, reason: not valid java name */
    public static final void m5966bindEvent$lambda14$lambda13(final PostDetailActivity this$0, final PostViewModel this_run, List it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this$0.setLoadingMoreSuccess(false);
        RecyclerView rv_post_comments = this$0.getRv_post_comments();
        rv_post_comments.setAdapter(this$0.getPostCommentListAdapter());
        if (this$0.getPageComment() == 1) {
            PostDetailActivity$postCommentListAdapter$2.C38671 postCommentListAdapter = this$0.getPostCommentListAdapter();
            Intrinsics.checkNotNullExpressionValue(it, "it");
            postCommentListAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) it));
            if (this$0.getPostCommentListAdapter().getData().size() == 0) {
                this$0.getRv_post_comments().setVisibility(8);
                this$0.getLl_postdetail_comment_loading().setVisibility(8);
                this$0.getLl_nodata_comment().setVisibility(0);
            }
        } else {
            List<CommentListBean> data = this$0.getPostCommentListAdapter().getData();
            Intrinsics.checkNotNullExpressionValue(it, "it");
            data.addAll(CollectionsKt___CollectionsKt.toMutableList((Collection) it));
            this$0.getPostCommentListAdapter().notifyDataSetChanged();
            if (CollectionsKt___CollectionsKt.toMutableList((Collection) it).size() < 15) {
                this$0.setNoMoreData(true);
                this$0.getProgress_comment().setVisibility(4);
                this$0.getTv_comment_loadstate().setText("没有更多数据了~");
            }
        }
        this$0.getTv_postdetail_comment().setText(this$0.getPostCommentListAdapter().getData().size() + "条评论");
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this$0);
        linearLayoutManager.setOrientation(1);
        Unit unit = Unit.INSTANCE;
        rv_post_comments.setLayoutManager(linearLayoutManager);
        if (rv_post_comments.getItemDecorationCount() == 0) {
            rv_post_comments.addItemDecoration(new ItemDecorationV(C2354n.m2425R(this$0, 2.0f), C2354n.m2425R(this$0, 2.0f)));
        }
        this$0.getSroll_postdetail().setOnScrollChangeListener(new NestedScrollView.OnScrollChangeListener() { // from class: b.a.a.a.t.k.f.u
            @Override // androidx.core.widget.NestedScrollView.OnScrollChangeListener
            public final void onScrollChange(NestedScrollView nestedScrollView, int i2, int i3, int i4, int i5) {
                PostDetailActivity.m5967bindEvent$lambda14$lambda13$lambda12(PostDetailActivity.this, this_run, nestedScrollView, i2, i3, i4, i5);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-14$lambda-13$lambda-12, reason: not valid java name */
    public static final void m5967bindEvent$lambda14$lambda13$lambda12(PostDetailActivity this$0, PostViewModel this_run, NestedScrollView nestedScrollView, int i2, int i3, int i4, int i5) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        if (i3 != nestedScrollView.getChildAt(0).getMeasuredHeight() - nestedScrollView.getMeasuredHeight() || this$0.getLoadingMoreSuccess() || this$0.getNoMoreData()) {
            return;
        }
        this$0.setPageComment(this$0.getPageComment() + 1);
        this$0.setLoadingMoreSuccess(true);
        this_run.commentLogs(this$0.getMPostId(), "post", this$0.getPageComment());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-14$lambda-9, reason: not valid java name */
    public static final void m5968bindEvent$lambda14$lambda9(final PostDetailActivity this$0, final PostViewModel this_run, PostDetailBean postDetailBean) {
        List<TagBean> list;
        List<PostDetailBean.GamesBean> list2;
        int i2;
        PostDetailBean.UserBean userBean;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this$0.getItv_favorite().setText(postDetailBean.has_favorite.equals("y") ? "已收藏" : "收藏");
        this$0.getItv_favorite().setSelected(postDetailBean.has_favorite.equals("y"));
        String str = null;
        if (Intrinsics.areEqual(postDetailBean.can_view, "n")) {
            this$0.getLl_postdetail_default().setVisibility(0);
            this$0.getRv_postdetail_files().setVisibility(8);
        } else {
            Intrinsics.checkNotNullExpressionValue(postDetailBean.links, "it.links");
            if (!r0.isEmpty()) {
                this$0.getRv_tag_post_games().setVisibility(0);
                RecyclerView rv_tag_post_games = this$0.getRv_tag_post_games();
                BaseQuickAdapter<PostDetailBean.GamesBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<PostDetailBean.GamesBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$1$1
                    @Override // com.chad.library.adapter.base.BaseQuickAdapter
                    public void convert(@NotNull BaseViewHolder helper, @NotNull PostDetailBean.GamesBean item) {
                        Intrinsics.checkNotNullParameter(helper, "helper");
                        Intrinsics.checkNotNullParameter(item, "item");
                        helper.m3919i(R.id.tv_content_gamename, String.valueOf(item.name));
                        helper.itemView.setTag(item.name);
                    }
                };
                baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.k.f.y
                    @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                    public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i3) {
                        PostDetailActivity.m5969bindEvent$lambda14$lambda9$lambda3$lambda1$lambda0(PostDetailActivity.this, baseQuickAdapter2, view, i3);
                    }
                });
                PostDetailBean value = this$0.getViewModel().getPostDetailBean().getValue();
                baseQuickAdapter.setNewData((value == null || (list2 = value.links) == null) ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list2));
                Unit unit = Unit.INSTANCE;
                rv_tag_post_games.setAdapter(baseQuickAdapter);
                FlexboxLayoutManager flexboxLayoutManager = new FlexboxLayoutManager(rv_tag_post_games.getContext());
                flexboxLayoutManager.m4176y(1);
                flexboxLayoutManager.m4175x(0);
                rv_tag_post_games.setLayoutManager(flexboxLayoutManager);
                if (rv_tag_post_games.getItemDecorationCount() == 0) {
                    GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_tag_post_games.getContext());
                    c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_tag_post_games, 2.0d);
                    c4053a.f10337e = C2354n.m2437V(rv_tag_post_games.getContext(), 3.0d);
                    C1499a.m604Z(c4053a, rv_tag_post_games);
                }
            } else {
                this$0.getRv_tag_post_games().setVisibility(8);
            }
            RecyclerView rv_tag_post = this$0.getRv_tag_post();
            BaseQuickAdapter<TagBean, BaseViewHolder> baseQuickAdapter2 = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$2$1
                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    helper.m3919i(R.id.tv_content, Intrinsics.stringPlus("#", item.name));
                    helper.itemView.setTag(item.f10032id);
                }
            };
            baseQuickAdapter2.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.k.f.x
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter3, View view, int i3) {
                    PostDetailActivity.m5970bindEvent$lambda14$lambda9$lambda7$lambda5$lambda4(PostDetailActivity.this, baseQuickAdapter3, view, i3);
                }
            });
            PostDetailBean value2 = this$0.getViewModel().getPostDetailBean().getValue();
            baseQuickAdapter2.setNewData((value2 == null || (list = value2.categories) == null) ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            Unit unit2 = Unit.INSTANCE;
            rv_tag_post.setAdapter(baseQuickAdapter2);
            FlexboxLayoutManager flexboxLayoutManager2 = new FlexboxLayoutManager(rv_tag_post.getContext());
            flexboxLayoutManager2.m4176y(1);
            flexboxLayoutManager2.m4175x(0);
            rv_tag_post.setLayoutManager(flexboxLayoutManager2);
            if (rv_tag_post.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(rv_tag_post.getContext());
                c4053a2.f10336d = C1499a.m638x(c4053a2, R.color.transparent, rv_tag_post, 2.0d);
                c4053a2.f10337e = C2354n.m2437V(rv_tag_post.getContext(), 3.0d);
                C1499a.m604Z(c4053a2, rv_tag_post);
            }
            this$0.getLl_postdetail_default().setVisibility(8);
            this$0.getRv_postdetail_files().setVisibility(0);
            RecyclerView rv_postdetail_files = this$0.getRv_postdetail_files();
            rv_postdetail_files.setAdapter(this$0.fileAdapter);
            PostDetailActivity$fileAdapter$1 postDetailActivity$fileAdapter$1 = this$0.fileAdapter;
            PostDetailBean value3 = this_run.getPostDetailBean().getValue();
            postDetailActivity$fileAdapter$1.setNewData(value3 == null ? null : value3.files);
            rv_postdetail_files.setLayoutManager(new LinearLayoutManager(this$0, 1, false));
            if (rv_postdetail_files.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a3 = new GridItemDecoration.C4053a(rv_postdetail_files.getContext());
                c4053a3.m4576a(R.color.transparent);
                rv_postdetail_files.addItemDecoration(new GridItemDecoration(c4053a3));
            }
        }
        String str2 = postDetailBean.user.f9976id;
        MyApp myApp = MyApp.f9891f;
        if (Intrinsics.areEqual(str2, MyApp.f9892g.user_id)) {
            this$0.getItv_postuser_follow().setVisibility(8);
        } else {
            C2354n.m2374A(this$0.getLl_posthome_usertop(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$4
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                    String str3;
                    Intrinsics.checkNotNullParameter(it, "it");
                    PostDetailBean value4 = PostViewModel.this.getPostDetailBean().getValue();
                    PostDetailBean.UserBean userBean2 = value4 == null ? null : value4.user;
                    if (userBean2 == null || (str3 = userBean2.f9976id) == null) {
                        return;
                    }
                    UserPostHomeActivity.Companion.start(this$0, str3);
                }
            }, 1);
        }
        this$0.getItv_postuser_follow().setVisibility(Intrinsics.areEqual(postDetailBean.user.f9976id, MyApp.f9892g.user_id) ? 8 : 0);
        if (Intrinsics.areEqual(postDetailBean.user.f9976id, MyApp.f9892g.user_id)) {
            this$0.getLl_mypost_time_del().setVisibility(0);
            C2354n.m2374A(this$0.getIv_mypost_del(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$5
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                    invoke2(imageView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull ImageView it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            }, 1);
        } else {
            this$0.getLl_mypost_time_del().setVisibility(8);
        }
        C2852c m2467d2 = C2354n.m2467d2(this$0);
        String str3 = postDetailBean.user.img;
        if (str3 == null) {
            str3 = "";
        }
        C1558h mo770c = m2467d2.mo770c();
        mo770c.mo763X(str3);
        ((C2851b) mo770c).m3292f0().m757R(this$0.getIv_userfollow_avatar());
        this$0.getIv_postitem_uper().setVisibility(Intrinsics.areEqual(postDetailBean.user.is_up, "y") ? 0 : 8);
        TextView tv_postdetail_nickname = this$0.getTv_postdetail_nickname();
        String str4 = postDetailBean.user.nickname;
        if (str4 == null) {
            str4 = "";
        }
        tv_postdetail_nickname.setText(str4);
        this$0.getIv_postitem_uservip().setVisibility(Intrinsics.areEqual(postDetailBean.user.is_vip, "y") ? 0 : 8);
        TextView tv_post_created_at = this$0.getTv_post_created_at();
        String stringPlus = Intrinsics.stringPlus("发布时间 ", postDetailBean.time);
        if (stringPlus == null) {
            stringPlus = "";
        }
        tv_post_created_at.setText(stringPlus);
        this$0.getItv_postuser_follow().setText(Intrinsics.areEqual(postDetailBean.user.is_follow, "y") ? "已关注" : "+关注");
        FollowTextView itv_postuser_follow = this$0.getItv_postuser_follow();
        PostDetailBean value4 = this_run.getPostDetailBean().getValue();
        if (value4 != null && (userBean = value4.user) != null) {
            str = userBean.is_follow;
        }
        itv_postuser_follow.setSelected(Intrinsics.areEqual(str, "y"));
        C2354n.m2374A(this$0.getItv_postuser_follow(), 0L, new Function1<FollowTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$6
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
                PostDetailBean.UserBean userBean2;
                PostDetailBean.UserBean userBean3;
                PostDetailBean.UserBean userBean4;
                String str5;
                PostViewModel viewModel;
                Intrinsics.checkNotNullParameter(it, "it");
                PostDetailBean value5 = PostViewModel.this.getPostDetailBean().getValue();
                if (Intrinsics.areEqual((value5 == null || (userBean2 = value5.user) == null) ? null : userBean2.is_follow, "y")) {
                    PostDetailBean value6 = PostViewModel.this.getPostDetailBean().getValue();
                    PostDetailBean.UserBean userBean5 = value6 == null ? null : value6.user;
                    if (userBean5 != null) {
                        userBean5.is_follow = "n";
                    }
                } else {
                    PostDetailBean value7 = PostViewModel.this.getPostDetailBean().getValue();
                    PostDetailBean.UserBean userBean6 = value7 == null ? null : value7.user;
                    if (userBean6 != null) {
                        userBean6.is_follow = "y";
                    }
                }
                FollowTextView itv_postuser_follow2 = this$0.getItv_postuser_follow();
                PostDetailBean value8 = PostViewModel.this.getPostDetailBean().getValue();
                itv_postuser_follow2.setText(Intrinsics.areEqual((value8 != null && (userBean3 = value8.user) != null) ? userBean3.is_follow : null, "y") ? "已关注" : "+关注");
                FollowTextView itv_postuser_follow3 = this$0.getItv_postuser_follow();
                PostDetailBean value9 = PostViewModel.this.getPostDetailBean().getValue();
                itv_postuser_follow3.setSelected(Intrinsics.areEqual((value9 == null || (userBean4 = value9.user) == null) ? null : userBean4.is_follow, "y"));
                PostDetailBean value10 = PostViewModel.this.getPostDetailBean().getValue();
                PostDetailBean.UserBean userBean7 = value10 != null ? value10.user : null;
                if (userBean7 == null || (str5 = userBean7.f9976id) == null) {
                    return;
                }
                final PostDetailActivity postDetailActivity = this$0;
                viewModel = postDetailActivity.getViewModel();
                viewModel.userDoFollow(str5, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$6$1$1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        PostDetailActivity.this.hideLoadingDialog();
                    }
                });
            }
        }, 1);
        this$0.getTv_posthome_childitemtitle().setText(postDetailBean.title);
        this$0.getTv_posthome_content().setMaxLines(99);
        this$0.getTv_posthome_content().setText(postDetailBean.content);
        if (Intrinsics.areEqual(postDetailBean.content, "")) {
            this$0.getTv_posthome_content().setVisibility(8);
        } else {
            this$0.getTv_posthome_content().setVisibility(0);
        }
        List<PostDetailBean.FilesBean> list3 = postDetailBean.files;
        if (list3 == null) {
            i2 = 8;
        } else if (list3.size() >= 3) {
            this$0.getLl_community_img_three().setVisibility(0);
            this$0.getLl_community_img_two().setVisibility(8);
            this$0.getLl_postitem_one().setVisibility(8);
            C2852c m2467d22 = C2354n.m2467d2(this$0);
            String str5 = postDetailBean.files.get(0).image;
            if (str5 == null) {
                str5 = "";
            }
            C1558h mo770c2 = m2467d22.mo770c();
            mo770c2.mo763X(str5);
            ((C2851b) mo770c2).m3295i0().m757R(this$0.getIv_community_img_twolft_posthome());
            C2354n.m2374A(this$0.getIv_community_img_twolft_posthome(), 0L, new Function1<ShapeableImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$7
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(ShapeableImageView shapeableImageView) {
                    invoke2(shapeableImageView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull ShapeableImageView it) {
                    PostViewModel viewModel;
                    Intrinsics.checkNotNullParameter(it, "it");
                    viewModel = PostDetailActivity.this.getViewModel();
                    PostDetailBean value5 = viewModel.getPostDetailBean().getValue();
                    if (value5 == null) {
                        return;
                    }
                    PostDetailActivity.this.noticeTips(value5);
                }
            }, 1);
            C2851b<Bitmap> mo769b = C2354n.m2467d2(this$0).mo769b();
            String str6 = postDetailBean.files.get(1).image;
            if (str6 == null) {
                str6 = "";
            }
            mo769b.f1865I = str6;
            mo769b.f1868L = true;
            mo769b.m3287a0(new C1779f().mo1080J(new C1704i(), new C1721z(15))).m3294h0(false).m3295i0().m757R(this$0.getIv_community_two_posthome());
            C2354n.m2374A(this$0.getIv_community_two_posthome(), 0L, new Function1<ShapeableImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$8
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(ShapeableImageView shapeableImageView) {
                    invoke2(shapeableImageView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull ShapeableImageView it) {
                    PostViewModel viewModel;
                    Intrinsics.checkNotNullParameter(it, "it");
                    viewModel = PostDetailActivity.this.getViewModel();
                    PostDetailBean value5 = viewModel.getPostDetailBean().getValue();
                    if (value5 == null) {
                        return;
                    }
                    PostDetailActivity.this.noticeTips(value5);
                }
            }, 1);
            C2851b<Bitmap> mo769b2 = C2354n.m2467d2(this$0).mo769b();
            String str7 = postDetailBean.files.get(2).image;
            mo769b2.f1865I = str7 != null ? str7 : "";
            mo769b2.f1868L = true;
            mo769b2.m3287a0(new C1779f().mo1080J(new C1704i(), new C1721z(15))).m3294h0(false).m3295i0().m757R(this$0.getIv_community_three_posthome());
            C2354n.m2374A(this$0.getIv_community_three_posthome(), 0L, new Function1<ShapeableImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$9
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(ShapeableImageView shapeableImageView) {
                    invoke2(shapeableImageView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull ShapeableImageView it) {
                    PostViewModel viewModel;
                    Intrinsics.checkNotNullParameter(it, "it");
                    viewModel = PostDetailActivity.this.getViewModel();
                    PostDetailBean value5 = viewModel.getPostDetailBean().getValue();
                    if (value5 == null) {
                        return;
                    }
                    PostDetailActivity.this.noticeTips(value5);
                }
            }, 1);
            if (Intrinsics.areEqual(postDetailBean.files.get(2).type, "image")) {
                i2 = 8;
                this$0.getIv_community_threevideo().setVisibility(8);
            } else {
                i2 = 8;
                this$0.getIv_community_threevideo().setVisibility(0);
            }
            if (Intrinsics.areEqual(postDetailBean.pay_type, VideoTypeBean.video_type_free)) {
                this$0.getItv_type_three_money().setVisibility(i2);
                this$0.getItv_type_three_vip().setVisibility(i2);
            } else if (Intrinsics.areEqual(postDetailBean.pay_type, "money")) {
                this$0.getItv_type_three_vip().setVisibility(i2);
                this$0.getItv_type_three_money().setVisibility(0);
            } else {
                this$0.getItv_type_three_vip().setVisibility(0);
                this$0.getItv_type_three_money().setVisibility(i2);
            }
        } else {
            i2 = 8;
            if (postDetailBean.files.size() == 2) {
                this$0.getLl_community_img_three().setVisibility(8);
                this$0.getLl_community_img_two().setVisibility(0);
                this$0.getLl_postitem_one().setVisibility(8);
                C2851b<Bitmap> mo769b3 = C2354n.m2467d2(this$0).mo769b();
                String str8 = postDetailBean.files.get(0).image;
                if (str8 == null) {
                    str8 = "";
                }
                mo769b3.f1865I = str8;
                mo769b3.f1868L = true;
                mo769b3.m3287a0(new C1779f().mo1080J(new C1704i(), new C1721z(15))).m3295i0().m757R(this$0.getIm_postdetail_two_left_());
                C2354n.m2374A(this$0.getIm_postdetail_two_left_(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$10
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
                        PostViewModel viewModel;
                        Intrinsics.checkNotNullParameter(it, "it");
                        viewModel = PostDetailActivity.this.getViewModel();
                        PostDetailBean value5 = viewModel.getPostDetailBean().getValue();
                        if (value5 == null) {
                            return;
                        }
                        PostDetailActivity.this.noticeTips(value5);
                    }
                }, 1);
                C2851b<Bitmap> mo769b4 = C2354n.m2467d2(this$0).mo769b();
                String str9 = postDetailBean.files.get(1).image;
                mo769b4.f1865I = str9 != null ? str9 : "";
                mo769b4.f1868L = true;
                mo769b4.m3287a0(new C1779f().mo1080J(new C1704i(), new C1721z(15))).m3295i0().m757R(this$0.getIm_postdetail_two_right_());
                C2354n.m2374A(this$0.getIm_postdetail_two_right_(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$11
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
                        PostViewModel viewModel;
                        Intrinsics.checkNotNullParameter(it, "it");
                        viewModel = PostDetailActivity.this.getViewModel();
                        PostDetailBean value5 = viewModel.getPostDetailBean().getValue();
                        if (value5 == null) {
                            return;
                        }
                        PostDetailActivity.this.noticeTips(value5);
                    }
                }, 1);
                if (Intrinsics.areEqual(postDetailBean.files.get(0).type, "image")) {
                    i2 = 8;
                    this$0.getIv_postdetail_two_type().setVisibility(8);
                } else {
                    this$0.getIv_postdetail_two_type().setVisibility(0);
                    i2 = 8;
                }
                if (Intrinsics.areEqual(postDetailBean.pay_type, VideoTypeBean.video_type_free)) {
                    this$0.getItv_type_two_money().setVisibility(i2);
                    this$0.getItv_type_two_vip().setVisibility(i2);
                } else if (Intrinsics.areEqual(postDetailBean.pay_type, "money")) {
                    this$0.getItv_type_two_vip().setVisibility(i2);
                    this$0.getItv_type_two_money().setVisibility(0);
                    this$0.getItv_type_two_money().setImageResource(R.drawable.coin_small);
                } else {
                    this$0.getItv_type_two_vip().setVisibility(0);
                    this$0.getItv_type_two_money().setVisibility(i2);
                }
            } else if (postDetailBean.files.size() == 1) {
                this$0.getLl_community_img_three().setVisibility(8);
                this$0.getLl_community_img_two().setVisibility(8);
                this$0.getLl_postitem_one().setVisibility(0);
                C2354n.m2467d2(this$0).m3298p(postDetailBean.files.get(0).image).m3295i0().m757R(this$0.getIm_community_img_single());
                ImageView view = this$0.getIm_community_img_single();
                Intrinsics.checkNotNullParameter(view, "view");
                view.setOutlineProvider(new C0859m0(3.0d));
                view.setClipToOutline(true);
                C2354n.m2374A(this$0.getIm_community_img_single(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$12
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
                        PostViewModel viewModel;
                        Intrinsics.checkNotNullParameter(it, "it");
                        viewModel = PostDetailActivity.this.getViewModel();
                        PostDetailBean value5 = viewModel.getPostDetailBean().getValue();
                        if (value5 == null) {
                            return;
                        }
                        PostDetailActivity.this.noticeTips(value5);
                    }
                }, 1);
                if (Intrinsics.areEqual(postDetailBean.files.get(0).type, "image")) {
                    i2 = 8;
                    this$0.getIv_postitem_pause().setVisibility(8);
                } else {
                    this$0.getIv_postitem_pause().setVisibility(0);
                    i2 = 8;
                }
                if (Intrinsics.areEqual(postDetailBean.pay_type, VideoTypeBean.video_type_free)) {
                    this$0.getItv_type_one_vip().setVisibility(i2);
                    this$0.getItv_type_one_money().setVisibility(i2);
                } else if (Intrinsics.areEqual(postDetailBean.pay_type, "money")) {
                    this$0.getItv_type_one_vip().setVisibility(i2);
                    this$0.getItv_type_one_money().setVisibility(0);
                } else {
                    this$0.getItv_type_one_vip().setVisibility(0);
                    this$0.getItv_type_one_money().setVisibility(i2);
                }
            } else {
                this$0.getLl_community_img_three().setVisibility(8);
                this$0.getLl_community_img_two().setVisibility(8);
                this$0.getLl_postitem_one().setVisibility(8);
            }
        }
        this$0.getTv_ll_line_postitem().setVisibility(i2);
        this$0.getItv_postitem_click().setText(C0843e0.m182a(postDetailBean.click));
        if (postDetailBean.comment.equals("0")) {
            this$0.getIv_count_comment().setText("评论");
        } else {
            this$0.getIv_count_comment().setText(C0843e0.m182a(postDetailBean.comment));
        }
        if (postDetailBean.love.equals("0")) {
            this$0.getItv_postitem_likes().setText("点赞");
        } else {
            this$0.getItv_postitem_likes().setText(C0843e0.m182a(postDetailBean.love));
        }
        this$0.getItv_postitem_likes().setSelected(Intrinsics.areEqual(postDetailBean.has_love, "y"));
        this$0.getItv_postitem_likes().setTextColor(Intrinsics.areEqual(postDetailBean.has_love, "y") ? this$0.getResources().getColor(R.color.color_E04A4A) : this$0.getResources().getColor(R.color.black40));
        C2354n.m2374A(this$0.getItv_postitem_likes(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$13
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
                String str10;
                PostViewModel viewModel;
                Intrinsics.checkNotNullParameter(it, "it");
                PostDetailBean value5 = PostViewModel.this.getPostDetailBean().getValue();
                if (Intrinsics.areEqual(value5 == null ? null : value5.has_love, "y")) {
                    PostDetailBean value6 = PostViewModel.this.getPostDetailBean().getValue();
                    if (value6 != null) {
                        PostDetailBean value7 = PostViewModel.this.getPostDetailBean().getValue();
                        value6.love = String.valueOf((value7 == null ? null : value7.love) == null ? null : Integer.valueOf(Integer.parseInt(r2) - 1));
                    }
                    PostDetailBean value8 = PostViewModel.this.getPostDetailBean().getValue();
                    if (value8 != null) {
                        value8.has_love = "n";
                    }
                    PostDetailBean value9 = PostViewModel.this.getPostDetailBean().getValue();
                    if (StringsKt__StringsJVMKt.equals$default(value9 == null ? null : value9.love, "0", false, 2, null)) {
                        ImageTextView itv_postitem_likes = this$0.getItv_postitem_likes();
                        PostDetailBean value10 = PostViewModel.this.getPostDetailBean().getValue();
                        itv_postitem_likes.setText(value10 == null ? null : value10.love);
                    } else {
                        ImageTextView itv_postitem_likes2 = this$0.getItv_postitem_likes();
                        PostDetailBean value11 = PostViewModel.this.getPostDetailBean().getValue();
                        itv_postitem_likes2.setText(C0843e0.m182a(value11 == null ? null : value11.love));
                    }
                } else {
                    PostDetailBean value12 = PostViewModel.this.getPostDetailBean().getValue();
                    if (value12 != null) {
                        PostDetailBean value13 = PostViewModel.this.getPostDetailBean().getValue();
                        String str11 = value13 == null ? null : value13.love;
                        value12.love = String.valueOf(str11 == null ? null : Integer.valueOf(Integer.parseInt(str11) + 1));
                    }
                    PostDetailBean value14 = PostViewModel.this.getPostDetailBean().getValue();
                    if (value14 != null) {
                        value14.has_love = "y";
                    }
                    ImageTextView itv_postitem_likes3 = this$0.getItv_postitem_likes();
                    PostDetailBean value15 = PostViewModel.this.getPostDetailBean().getValue();
                    itv_postitem_likes3.setText(C0843e0.m182a(value15 == null ? null : value15.love));
                }
                ImageTextView itv_postitem_likes4 = this$0.getItv_postitem_likes();
                PostDetailBean value16 = PostViewModel.this.getPostDetailBean().getValue();
                itv_postitem_likes4.setTextColor(Intrinsics.areEqual(value16 == null ? null : value16.has_love, "y") ? this$0.getResources().getColor(R.color.color_E04A4A) : this$0.getResources().getColor(R.color.black40));
                ImageTextView itv_postitem_likes5 = this$0.getItv_postitem_likes();
                PostDetailBean value17 = PostViewModel.this.getPostDetailBean().getValue();
                itv_postitem_likes5.setSelected(Intrinsics.areEqual(value17 != null ? value17.has_love : null, "y"));
                PostDetailBean value18 = PostViewModel.this.getPostDetailBean().getValue();
                if (value18 == null || (str10 = value18.f9974id) == null) {
                    return;
                }
                final PostDetailActivity postDetailActivity = this$0;
                viewModel = postDetailActivity.getViewModel();
                viewModel.postDoLove(str10, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$13$1$1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        PostDetailActivity.this.hideLoadingDialog();
                    }
                });
            }
        }, 1);
        C2354n.m2374A(this$0.getLl_share_postitem(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$1$14
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
                Intrinsics.checkNotNullParameter(it, "it");
                InviteActivity.INSTANCE.start(PostDetailActivity.this);
            }
        }, 1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-14$lambda-9$lambda-3$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5969bindEvent$lambda14$lambda9$lambda3$lambda1$lambda0(PostDetailActivity this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.PostDetailBean.GamesBean");
        C0840d.a aVar = C0840d.f235a;
        String str = ((PostDetailBean.GamesBean) obj).url;
        Intrinsics.checkNotNullExpressionValue(str, "item.url");
        aVar.m175a(this$0, str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-14$lambda-9$lambda-7$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5970bindEvent$lambda14$lambda9$lambda7$lambda5$lambda4(PostDetailActivity this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
        PostCategoryDetailActivity.Companion companion = PostCategoryDetailActivity.INSTANCE;
        String str = ((TagBean) obj).f10032id;
        Intrinsics.checkNotNullExpressionValue(str, "item.id");
        companion.start(this$0, str, "normal");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void checkMoneyForBuyPost$default(PostDetailActivity postDetailActivity, PostDetailBean postDetailBean, Function1 function1, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$checkMoneyForBuyPost$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                    invoke(bool.booleanValue());
                    return Unit.INSTANCE;
                }

                public final void invoke(boolean z) {
                }
            };
        }
        postDetailActivity.checkMoneyForBuyPost(postDetailBean, function1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMPostId() {
        return (String) this.mPostId.getValue();
    }

    private final PostDetailActivity$postCommentListAdapter$2.C38671 getPostCommentListAdapter() {
        return (PostDetailActivity$postCommentListAdapter$2.C38671) this.postCommentListAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getShowLoveTxt(String love) {
        return ((love == null || StringsKt__StringsJVMKt.isBlank(love)) || TextUtils.equals("0", love)) ? "0" : C0843e0.m182a(love);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayMap<String, String> getVideoPlayHeader() {
        return (ArrayMap) this.videoPlayHeader.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final PostViewModel getViewModel() {
        return (PostViewModel) this.viewModel.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void noticeTips(final PostDetailBean postDetailBean) {
        String str = postDetailBean.money;
        Intrinsics.checkNotNullExpressionValue(str, "postDetailBean.money");
        String str2 = postDetailBean.pay_type;
        Intrinsics.checkNotNullExpressionValue(str2, "postDetailBean.pay_type");
        new BuyDialog(str, str2, "此帖需要购买可查看详情", new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$noticeTips$1
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
                    if (!Intrinsics.areEqual(PostDetailBean.this.pay_type, "money")) {
                        BuyActivity.INSTANCE.start(this);
                    } else {
                        final PostDetailActivity postDetailActivity = this;
                        postDetailActivity.checkMoneyForBuyPost(PostDetailBean.this, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$noticeTips$1.1
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                                invoke(bool.booleanValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(boolean z2) {
                                PostViewModel viewModel;
                                String mPostId;
                                if (!z2) {
                                    RechargeActivity.INSTANCE.start(PostDetailActivity.this);
                                    return;
                                }
                                viewModel = PostDetailActivity.this.getViewModel();
                                mPostId = PostDetailActivity.this.getMPostId();
                                final PostDetailActivity postDetailActivity2 = PostDetailActivity.this;
                                PostViewModel.postDoBuy$default(viewModel, mPostId, false, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity.noticeTips.1.1.1
                                    {
                                        super(1);
                                    }

                                    @Override // kotlin.jvm.functions.Function1
                                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                                        invoke(bool.booleanValue());
                                        return Unit.INSTANCE;
                                    }

                                    public final void invoke(boolean z3) {
                                        PostViewModel viewModel2;
                                        String mPostId2;
                                        PostDetailActivity.this.hideLoadingDialog();
                                        if (z3) {
                                            C2354n.m2409L1("购买成功");
                                            viewModel2 = PostDetailActivity.this.getViewModel();
                                            mPostId2 = PostDetailActivity.this.getMPostId();
                                            viewModel2.postDetail(mPostId2);
                                        }
                                    }
                                }, 2, null);
                            }
                        });
                    }
                }
            }
        }).show(getSupportFragmentManager(), "buyDialog");
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getItv_favorite().setVisibility(0);
        final PostViewModel viewModel = getViewModel();
        viewModel.postDetail(getMPostId());
        viewModel.commentLogs(getMPostId(), "post", getPageComment());
        viewModel.getPostDetailBean().observe(this, new Observer() { // from class: b.a.a.a.t.k.f.s
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PostDetailActivity.m5968bindEvent$lambda14$lambda9(PostDetailActivity.this, viewModel, (PostDetailBean) obj);
            }
        });
        viewModel.getMCommentListBean().observe(this, new Observer() { // from class: b.a.a.a.t.k.f.t
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PostDetailActivity.m5966bindEvent$lambda14$lambda13(PostDetailActivity.this, viewModel, (List) obj);
            }
        });
        C2354n.m2374A(getItv_confirm_post(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$3
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
                PostViewModel viewModel2;
                String mPostId;
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(String.valueOf(PostDetailActivity.this.getEd_input_comment().getText()), "")) {
                    C2354n.m2449Z("请输入评论内容");
                    return;
                }
                viewModel2 = PostDetailActivity.this.getViewModel();
                mPostId = PostDetailActivity.this.getMPostId();
                String valueOf = String.valueOf(PostDetailActivity.this.getEd_input_comment().getText());
                final PostDetailActivity postDetailActivity = PostDetailActivity.this;
                final PostViewModel postViewModel = viewModel;
                viewModel2.commentDo(mPostId, valueOf, "post", (r12 & 8) != 0 ? false : false, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$3.1
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
                        String mPostId2;
                        if (z) {
                            PostDetailActivity.this.getEd_input_comment().setText("");
                            PostViewModel postViewModel2 = postViewModel;
                            mPostId2 = PostDetailActivity.this.getMPostId();
                            postViewModel2.commentLogs(mPostId2, "post", 1);
                        }
                        PostDetailActivity.this.hideLoadingDialog();
                    }
                });
            }
        }, 1);
        C2354n.m2374A(getItv_favorite(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$4
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
                PostViewModel viewModel2;
                String mPostId;
                Intrinsics.checkNotNullParameter(it, "it");
                viewModel2 = PostDetailActivity.this.getViewModel();
                mPostId = PostDetailActivity.this.getMPostId();
                final PostViewModel postViewModel = viewModel;
                final PostDetailActivity postDetailActivity = PostDetailActivity.this;
                PostViewModel.postDoFavorite$default(viewModel2, mPostId, true, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$bindEvent$1$4.1
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
                        PostDetailBean value = PostViewModel.this.getPostDetailBean().getValue();
                        if (StringsKt__StringsJVMKt.equals$default(value == null ? null : value.has_favorite, "y", false, 2, null)) {
                            PostDetailBean value2 = PostViewModel.this.getPostDetailBean().getValue();
                            if (value2 != null) {
                                value2.has_favorite = "n";
                            }
                        } else {
                            PostDetailBean value3 = PostViewModel.this.getPostDetailBean().getValue();
                            if (value3 != null) {
                                value3.has_favorite = "y";
                            }
                        }
                        ImageTextView itv_favorite = postDetailActivity.getItv_favorite();
                        PostDetailBean value4 = PostViewModel.this.getPostDetailBean().getValue();
                        itv_favorite.setText(StringsKt__StringsJVMKt.equals$default(value4 == null ? null : value4.has_favorite, "y", false, 2, null) ? "已收藏" : "收藏");
                        ImageTextView itv_favorite2 = postDetailActivity.getItv_favorite();
                        PostDetailBean value5 = PostViewModel.this.getPostDetailBean().getValue();
                        itv_favorite2.setSelected(StringsKt__StringsJVMKt.equals$default(value5 == null ? null : value5.has_favorite, "y", false, 2, null));
                        postDetailActivity.hideLoadingDialog();
                    }
                }, null, 8, null);
            }
        }, 1);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x001d  */
    /* JADX WARN: Removed duplicated region for block: B:12:0x0023  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x002e  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0030  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0024 A[Catch: Exception -> 0x0029, TRY_LEAVE, TryCatch #0 {Exception -> 0x0029, blocks: (B:8:0x0017, B:20:0x0024, B:22:0x001f), top: B:7:0x0017 }] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x001f A[Catch: Exception -> 0x0029, TryCatch #0 {Exception -> 0x0029, blocks: (B:8:0x0017, B:20:0x0024, B:22:0x001f), top: B:7:0x0017 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void checkMoneyForBuyPost(@org.jetbrains.annotations.NotNull com.jbzd.media.movecartoons.bean.response.PostDetailBean r5, @org.jetbrains.annotations.NotNull kotlin.jvm.functions.Function1<? super java.lang.Boolean, kotlin.Unit> r6) {
        /*
            r4 = this;
            java.lang.String r0 = "postDetailBean"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            java.lang.String r0 = "result"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            r0 = 0
            java.lang.String r5 = r5.money     // Catch: java.lang.Exception -> L16
            if (r5 != 0) goto L11
            goto L16
        L11:
            double r2 = java.lang.Double.parseDouble(r5)     // Catch: java.lang.Exception -> L16
            goto L17
        L16:
            r2 = r0
        L17:
            com.jbzd.media.movecartoons.MyApp r5 = com.jbzd.media.movecartoons.MyApp.f9891f     // Catch: java.lang.Exception -> L29
            com.jbzd.media.movecartoons.bean.response.UserInfoBean r5 = com.jbzd.media.movecartoons.MyApp.f9892g     // Catch: java.lang.Exception -> L29
            if (r5 != 0) goto L1f
            r5 = 0
            goto L21
        L1f:
            java.lang.String r5 = r5.balance     // Catch: java.lang.Exception -> L29
        L21:
            if (r5 != 0) goto L24
            goto L2a
        L24:
            double r0 = java.lang.Double.parseDouble(r5)     // Catch: java.lang.Exception -> L29
            goto L2a
        L29:
        L2a:
            int r5 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r5 < 0) goto L30
            r5 = 1
            goto L31
        L30:
            r5 = 0
        L31:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            r6.invoke(r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.post.topic.PostDetailActivity.checkMoneyForBuyPost(com.jbzd.media.movecartoons.bean.response.PostDetailBean, kotlin.jvm.functions.Function1):void");
    }

    @NotNull
    public final ImageView getBack() {
        return (ImageView) this.back.getValue();
    }

    @NotNull
    public final AppCompatEditText getEd_input_comment() {
        return (AppCompatEditText) this.ed_input_comment.getValue();
    }

    @NotNull
    public final ImageView getIm_community_img_single() {
        return (ImageView) this.im_community_img_single.getValue();
    }

    @NotNull
    public final ImageView getIm_postdetail_two_left_() {
        return (ImageView) this.im_postdetail_two_left_.getValue();
    }

    @NotNull
    public final ImageView getIm_postdetail_two_right_() {
        return (ImageView) this.im_postdetail_two_right_.getValue();
    }

    @NotNull
    public final ImageTextView getItv_confirm_post() {
        return (ImageTextView) this.itv_confirm_post.getValue();
    }

    @NotNull
    public final ImageTextView getItv_favorite() {
        return (ImageTextView) this.itv_favorite.getValue();
    }

    @NotNull
    public final ImageTextView getItv_postitem_click() {
        return (ImageTextView) this.itv_postitem_click.getValue();
    }

    @NotNull
    public final ImageTextView getItv_postitem_likes() {
        return (ImageTextView) this.itv_postitem_likes.getValue();
    }

    @NotNull
    public final FollowTextView getItv_postuser_follow() {
        return (FollowTextView) this.itv_postuser_follow.getValue();
    }

    @NotNull
    public final ImageView getItv_type_one_money() {
        return (ImageView) this.itv_type_one_money.getValue();
    }

    @NotNull
    public final ImageTextView getItv_type_one_vip() {
        return (ImageTextView) this.itv_type_one_vip.getValue();
    }

    @NotNull
    public final ImageView getItv_type_three_money() {
        return (ImageView) this.itv_type_three_money.getValue();
    }

    @NotNull
    public final ImageTextView getItv_type_three_vip() {
        return (ImageTextView) this.itv_type_three_vip.getValue();
    }

    @NotNull
    public final ImageView getItv_type_two_money() {
        return (ImageView) this.itv_type_two_money.getValue();
    }

    @NotNull
    public final ImageTextView getItv_type_two_vip() {
        return (ImageTextView) this.itv_type_two_vip.getValue();
    }

    @NotNull
    public final ShapeableImageView getIv_community_img_twolft_posthome() {
        return (ShapeableImageView) this.iv_community_img_twolft_posthome.getValue();
    }

    @NotNull
    public final ShapeableImageView getIv_community_three_posthome() {
        return (ShapeableImageView) this.iv_community_three_posthome.getValue();
    }

    @NotNull
    public final ImageView getIv_community_threevideo() {
        return (ImageView) this.iv_community_threevideo.getValue();
    }

    @NotNull
    public final ShapeableImageView getIv_community_two_posthome() {
        return (ShapeableImageView) this.iv_community_two_posthome.getValue();
    }

    @NotNull
    public final ImageTextView getIv_count_comment() {
        return (ImageTextView) this.iv_count_comment.getValue();
    }

    @NotNull
    public final ImageView getIv_mypost_del() {
        return (ImageView) this.iv_mypost_del.getValue();
    }

    @NotNull
    public final ImageView getIv_postdetail_two_type() {
        return (ImageView) this.iv_postdetail_two_type.getValue();
    }

    @NotNull
    public final ImageView getIv_postitem_pause() {
        return (ImageView) this.iv_postitem_pause.getValue();
    }

    @NotNull
    public final ImageView getIv_postitem_uper() {
        return (ImageView) this.iv_postitem_uper.getValue();
    }

    @NotNull
    public final ImageView getIv_postitem_uservip() {
        return (ImageView) this.iv_postitem_uservip.getValue();
    }

    @NotNull
    public final CircleImageView getIv_userfollow_avatar() {
        return (CircleImageView) this.iv_userfollow_avatar.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_post_details;
    }

    @NotNull
    public final LinearLayout getLl_community_img_three() {
        return (LinearLayout) this.ll_community_img_three.getValue();
    }

    @NotNull
    public final LinearLayout getLl_community_img_two() {
        return (LinearLayout) this.ll_community_img_two.getValue();
    }

    @NotNull
    public final LinearLayout getLl_mypost_time_del() {
        return (LinearLayout) this.ll_mypost_time_del.getValue();
    }

    @NotNull
    public final ImageTextView getLl_nodata_comment() {
        return (ImageTextView) this.ll_nodata_comment.getValue();
    }

    @NotNull
    public final LinearLayout getLl_postdetail_comment_loading() {
        return (LinearLayout) this.ll_postdetail_comment_loading.getValue();
    }

    @NotNull
    public final LinearLayout getLl_postdetail_default() {
        return (LinearLayout) this.ll_postdetail_default.getValue();
    }

    @NotNull
    public final LinearLayout getLl_posthome_usertop() {
        return (LinearLayout) this.ll_posthome_usertop.getValue();
    }

    @NotNull
    public final RelativeLayout getLl_postitem_one() {
        return (RelativeLayout) this.ll_postitem_one.getValue();
    }

    @NotNull
    public final LinearLayout getLl_share_postitem() {
        return (LinearLayout) this.ll_share_postitem.getValue();
    }

    public final boolean getLoadingMoreSuccess() {
        return this.loadingMoreSuccess;
    }

    public final boolean getNoMoreData() {
        return this.noMoreData;
    }

    public final int getPageComment() {
        return this.pageComment;
    }

    @Nullable
    public final FullPlayerView getPlayer_postdetail() {
        return this.player_postdetail;
    }

    @NotNull
    public final ProgressBar getProgress_comment() {
        return (ProgressBar) this.progress_comment.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getRightTitle() {
        return "";
    }

    @NotNull
    public final RecyclerView getRv_post_comments() {
        return (RecyclerView) this.rv_post_comments.getValue();
    }

    @NotNull
    public final RecyclerView getRv_postdetail_files() {
        return (RecyclerView) this.rv_postdetail_files.getValue();
    }

    @NotNull
    public final RecyclerView getRv_tag_post() {
        return (RecyclerView) this.rv_tag_post.getValue();
    }

    @NotNull
    public final RecyclerView getRv_tag_post_games() {
        return (RecyclerView) this.rv_tag_post_games.getValue();
    }

    @NotNull
    public final NestedScrollView getSroll_postdetail() {
        return (NestedScrollView) this.sroll_postdetail.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "帖子详情";
    }

    @NotNull
    public final TextView getTv_comment_loadstate() {
        return (TextView) this.tv_comment_loadstate.getValue();
    }

    @NotNull
    public final TextView getTv_ll_line_postitem() {
        return (TextView) this.tv_ll_line_postitem.getValue();
    }

    @NotNull
    public final TextView getTv_post_created_at() {
        return (TextView) this.tv_post_created_at.getValue();
    }

    @NotNull
    public final TextView getTv_postdetail_comment() {
        return (TextView) this.tv_postdetail_comment.getValue();
    }

    @NotNull
    public final TextView getTv_postdetail_nickname() {
        return (TextView) this.tv_postdetail_nickname.getValue();
    }

    @NotNull
    public final AppCompatTextView getTv_posthome_childitemtitle() {
        return (AppCompatTextView) this.tv_posthome_childitemtitle.getValue();
    }

    @NotNull
    public final TextView getTv_posthome_content() {
        return (TextView) this.tv_posthome_content.getValue();
    }

    public final void loadPreviewImage(@NotNull Context context, @NotNull String url, @NotNull ImageView target) {
        String str;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(target, "target");
        C1779f c1779f = new C1779f();
        AbstractC1643k abstractC1643k = AbstractC1643k.f2222a;
        C1779f mo1097x = c1779f.mo1086i(abstractC1643k).mo1097x(Integer.MIN_VALUE, Integer.MIN_VALUE);
        EnumC1570b enumC1570b = EnumC1570b.PREFER_RGB_565;
        C1779f mo1088l = mo1097x.mo1090n(enumC1570b).mo1098y(R.drawable.ic_place_holder_vertical).mo1088l(R.drawable.ic_place_holder_vertical);
        Intrinsics.checkNotNullExpressionValue(mo1088l, "RequestOptions()\n            .diskCacheStrategy(DiskCacheStrategy.ALL)\n            .override(Target.SIZE_ORIGINAL, Target.SIZE_ORIGINAL)//关键代码，加载原始大小\n            .format(DecodeFormat.PREFER_RGB_565)//设置为这种格式去掉透明度通道，可以减少内存占有\n            .placeholder(\n                R.drawable.ic_place_holder_vertical\n            )\n            .error(R.drawable.ic_place_holder_vertical)");
        C1779f c1779f2 = mo1088l;
        C1779f mo1088l2 = new C1779f().mo1086i(abstractC1643k).mo1097x(Integer.MIN_VALUE, Integer.MIN_VALUE).mo1090n(enumC1570b).mo1098y(R.drawable.ic_place_holder_vertical_51).mo1088l(R.drawable.ic_place_holder_vertical_51);
        Intrinsics.checkNotNullExpressionValue(mo1088l2, "RequestOptions()\n            .diskCacheStrategy(DiskCacheStrategy.ALL)\n            .override(Target.SIZE_ORIGINAL, Target.SIZE_ORIGINAL)//关键代码，加载原始大小\n            .format(DecodeFormat.PREFER_RGB_565)//设置为这种格式去掉透明度通道，可以减少内存占有\n            .placeholder(\n                R.drawable.ic_place_holder_vertical_51\n            )\n            .error(R.drawable.ic_place_holder_vertical_51)");
        C1779f c1779f3 = mo1088l2;
        ApplicationC2828a context2 = C2827a.f7670a;
        if (context2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        Intrinsics.checkNotNullParameter(context2, "context");
        try {
            PackageManager packageManager = context2.getPackageManager();
            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context2.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
            str = (String) packageManager.getApplicationLabel(applicationInfo);
        } catch (PackageManager.NameNotFoundException unused) {
            str = "";
        }
        if (Intrinsics.areEqual(str != null ? Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(str, "九妖", false, 2, null)) : null, Boolean.TRUE)) {
            ComponentCallbacks2C1553c.m738h(context).mo778k(c1779f2).mo775h(url).m757R(target);
        } else {
            ComponentCallbacks2C1553c.m738h(context).mo778k(c1779f3).mo775h(url).m757R(target);
        }
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (C2920c.m3393b(this)) {
            return;
        }
        super.onBackPressed();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        FullPlayerView fullPlayerView = this.player_postdetail;
        if (fullPlayerView != null) {
            Intrinsics.checkNotNull(fullPlayerView);
            fullPlayerView.onVideoPause();
            FullPlayerView fullPlayerView2 = this.player_postdetail;
            Intrinsics.checkNotNull(fullPlayerView2);
            fullPlayerView2.release();
        }
        C2920c.m3397f();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        super.onPause();
        FullPlayerView fullPlayerView = this.player_postdetail;
        if (fullPlayerView == null) {
            return;
        }
        fullPlayerView.onVideoPause();
    }

    public final void setLoadingMoreSuccess(boolean z) {
        this.loadingMoreSuccess = z;
    }

    public final void setNoMoreData(boolean z) {
        this.noMoreData = z;
    }

    public final void setPageComment(int i2) {
        this.pageComment = i2;
    }

    public final void setPlayer_postdetail(@Nullable FullPlayerView fullPlayerView) {
        this.player_postdetail = fullPlayerView;
    }

    @NotNull
    public final PostViewModel viewModelInstance() {
        return getViewModel();
    }
}

package com.jbzd.media.movecartoons.p396ui.movie;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.os.Handler;
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
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.github.mmin18.widget.RealtimeBlurView;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.comics.CommentFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.UpgradePriceDialog;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity$spinnerAdapter$2;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsViewModel;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.ProgressButton;
import com.jbzd.media.movecartoons.view.XDividerItemDecoration;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.jbzd.media.movecartoons.view.video.MyVideoAllCallback;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import com.youth.banner.listener.OnPageChangeListener;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.ranges.IntRange;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p009a.C0851i0;
import p005b.p006a.p007a.p008a.p009a.C0853j0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p005b.p327w.p330b.p336c.C2852c;
import p005b.p362y.p363a.C2920c;
import p005b.p362y.p363a.p366f.InterfaceC2927c;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.p381a.C2964m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0088\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\t\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0019\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002*\u0002Ë\u0001\u0018\u0000 Ù\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002Ù\u0001B\b¢\u0006\u0005\bØ\u0001\u0010#J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u001f\u0010\u000b\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u001f\u0010\u000e\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\r\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u000e\u0010\fJ\u001f\u0010\u0013\u001a\u00020\u00052\u0006\u0010\u0010\u001a\u00020\u000f2\u0006\u0010\u0012\u001a\u00020\u0011H\u0002¢\u0006\u0004\b\u0013\u0010\u0014J\u0017\u0010\u0015\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b\u0015\u0010\u0016J%\u0010\u001b\u001a\u00020\u00052\f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00180\u00172\u0006\u0010\u001a\u001a\u00020\u0011H\u0003¢\u0006\u0004\b\u001b\u0010\u001cJ\u0017\u0010\u001f\u001a\u00020\u00052\u0006\u0010\u001e\u001a\u00020\u001dH\u0002¢\u0006\u0004\b\u001f\u0010 J\u0017\u0010!\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b!\u0010\u0016J\u000f\u0010\"\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\"\u0010#J\u000f\u0010$\u001a\u00020\u000fH\u0016¢\u0006\u0004\b$\u0010%J\u0019\u0010(\u001a\u00020\u00052\b\u0010'\u001a\u0004\u0018\u00010&H\u0014¢\u0006\u0004\b(\u0010)J\u0019\u0010,\u001a\u00020\u00052\b\u0010+\u001a\u0004\u0018\u00010*H\u0014¢\u0006\u0004\b,\u0010-J\u000f\u0010.\u001a\u00020\u0005H\u0014¢\u0006\u0004\b.\u0010#J\u000f\u0010/\u001a\u00020\u0005H\u0014¢\u0006\u0004\b/\u0010#J\u000f\u00100\u001a\u00020\u0005H\u0014¢\u0006\u0004\b0\u0010#J\u000f\u00101\u001a\u00020\u0005H\u0016¢\u0006\u0004\b1\u0010#J\u000f\u00102\u001a\u00020\u0005H\u0014¢\u0006\u0004\b2\u0010#J\u000f\u00103\u001a\u00020\u0005H\u0016¢\u0006\u0004\b3\u0010#J\r\u00105\u001a\u000204¢\u0006\u0004\b5\u00106J\u000f\u00107\u001a\u00020\u0002H\u0016¢\u0006\u0004\b7\u00108R\u001d\u0010>\u001a\u0002098B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b:\u0010;\u001a\u0004\b<\u0010=R\u001d\u0010C\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b@\u0010;\u001a\u0004\bA\u0010BR\u001d\u0010H\u001a\u00020D8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010;\u001a\u0004\bF\u0010GR\u001d\u0010K\u001a\u00020D8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010;\u001a\u0004\bJ\u0010GR\u001d\u0010N\u001a\u00020\u00028V@\u0016X\u0096\u0084\u0002¢\u0006\f\n\u0004\bL\u0010;\u001a\u0004\bM\u00108R\u0018\u0010O\u001a\u0004\u0018\u00010\u00118\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bO\u0010PR\u001d\u0010S\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bQ\u0010;\u001a\u0004\bR\u0010BR\u0018\u0010U\u001a\u0004\u0018\u00010T8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bU\u0010VR\u001d\u0010[\u001a\u00020W8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bX\u0010;\u001a\u0004\bY\u0010ZR\u001d\u0010`\u001a\u00020\\8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010;\u001a\u0004\b^\u0010_R\u001d\u0010e\u001a\u00020a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bb\u0010;\u001a\u0004\bc\u0010dR\u001d\u0010j\u001a\u00020f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bg\u0010;\u001a\u0004\bh\u0010iR\"\u0010l\u001a\u00020k8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bl\u0010m\u001a\u0004\bn\u0010o\"\u0004\bp\u0010qR\u001d\u0010v\u001a\u00020r8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bs\u0010;\u001a\u0004\bt\u0010uR\u0018\u0010w\u001a\u0004\u0018\u00010\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bw\u0010xR\u001d\u0010}\u001a\u00020y8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bz\u0010;\u001a\u0004\b{\u0010|R\u001e\u0010\u0080\u0001\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b~\u0010;\u001a\u0004\b\u007f\u0010BR\u0019\u0010\u0081\u0001\u001a\u00020\u00038\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\b\u0081\u0001\u0010\u0082\u0001R \u0010\u0085\u0001\u001a\u00020f8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0083\u0001\u0010;\u001a\u0005\b\u0084\u0001\u0010iR\"\u0010\u008a\u0001\u001a\u00030\u0086\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0087\u0001\u0010;\u001a\u0006\b\u0088\u0001\u0010\u0089\u0001R\u001c\u0010\u008c\u0001\u001a\u0005\u0018\u00010\u008b\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\b\u008c\u0001\u0010\u008d\u0001R\"\u0010\u0092\u0001\u001a\u00030\u008e\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u008f\u0001\u0010;\u001a\u0006\b\u0090\u0001\u0010\u0091\u0001R \u0010\u0095\u0001\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0093\u0001\u0010;\u001a\u0005\b\u0094\u0001\u0010BR\"\u0010\u009a\u0001\u001a\u00030\u0096\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0097\u0001\u0010;\u001a\u0006\b\u0098\u0001\u0010\u0099\u0001R \u0010\u009d\u0001\u001a\u00020f8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u009b\u0001\u0010;\u001a\u0005\b\u009c\u0001\u0010iR.\u0010¢\u0001\u001a\u000f\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u00110\u009e\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u009f\u0001\u0010;\u001a\u0006\b \u0001\u0010¡\u0001R \u0010¥\u0001\u001a\u00020\\8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b£\u0001\u0010;\u001a\u0005\b¤\u0001\u0010_R \u0010¨\u0001\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b¦\u0001\u0010;\u001a\u0005\b§\u0001\u0010BR \u0010«\u0001\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b©\u0001\u0010;\u001a\u0005\bª\u0001\u0010BR \u0010®\u0001\u001a\u00020f8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b¬\u0001\u0010;\u001a\u0005\b\u00ad\u0001\u0010iR \u0010±\u0001\u001a\u00020f8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b¯\u0001\u0010;\u001a\u0005\b°\u0001\u0010iR \u0010´\u0001\u001a\u00020f8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b²\u0001\u0010;\u001a\u0005\b³\u0001\u0010iR \u0010·\u0001\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bµ\u0001\u0010;\u001a\u0005\b¶\u0001\u0010BR\"\u0010¼\u0001\u001a\u00030¸\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b¹\u0001\u0010;\u001a\u0006\bº\u0001\u0010»\u0001R \u0010¿\u0001\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b½\u0001\u0010;\u001a\u0005\b¾\u0001\u0010BR \u0010Â\u0001\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bÀ\u0001\u0010;\u001a\u0005\bÁ\u0001\u0010BR*\u0010Ç\u0001\u001a\u000b\u0012\u0002\b\u0003\u0012\u0002\b\u00030Ã\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\bÄ\u0001\u0010;\u001a\u0006\bÅ\u0001\u0010Æ\u0001R \u0010Ê\u0001\u001a\u00020f8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\bÈ\u0001\u0010;\u001a\u0005\bÉ\u0001\u0010iR\"\u0010Ï\u0001\u001a\u00030Ë\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\bÌ\u0001\u0010;\u001a\u0006\bÍ\u0001\u0010Î\u0001R(\u0010Ð\u0001\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\bÐ\u0001\u0010Ñ\u0001\u001a\u0005\bÒ\u0001\u0010%\"\u0006\bÓ\u0001\u0010Ô\u0001R\u001c\u0010Ö\u0001\u001a\u0005\u0018\u00010Õ\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bÖ\u0001\u0010×\u0001¨\u0006Ý\u0001²\u0006!\u0010Ü\u0001\u001a\u0014\u0012\u0004\u0012\u00020\u00110Ú\u0001j\t\u0012\u0004\u0012\u00020\u0011`Û\u00018\n@\nX\u008a\u0084\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;", "", "show", "", "bindPreviewPriceCover", "(Z)V", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "video", "isPreviewVideo", "bindPriceCover", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;Z)V", "isPreviewEnd", "priceDialog", "", "time", "", "jump", "countDown", "(ILjava/lang/String;)V", "initView", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;)V", "", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$PlayLinksBean;", "links", "link_name", "initSpinner", "(Ljava/util/List;Ljava/lang/String;)V", "", "counts", "getCountDownTime", "(J)V", "doBuyVideo", "initPlay", "()V", "getLayoutId", "()I", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Landroid/content/Intent;", "intent", "onNewIntent", "(Landroid/content/Intent;)V", "onStop", "onPause", "onResume", "onBackPressed", "onDestroy", "bindEvent", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;", "Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment;", "mMovieDescFragment$delegate", "Lkotlin/Lazy;", "getMMovieDescFragment", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment;", "mMovieDescFragment", "Landroid/widget/TextView;", "tv_sec$delegate", "getTv_sec", "()Landroid/widget/TextView;", "tv_sec", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_replay$delegate", "getItv_replay", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_replay", "tv_spinner$delegate", "getTv_spinner", "tv_spinner", "viewModel$delegate", "getViewModel", "viewModel", "mId", "Ljava/lang/String;", "tv_time_count_down$delegate", "getTv_time_count_down", "tv_time_count_down", "Landroid/widget/PopupWindow;", "popWindow", "Landroid/widget/PopupWindow;", "Lcom/jbzd/media/movecartoons/view/video/FullPlayerView;", "full_player$delegate", "getFull_player", "()Lcom/jbzd/media/movecartoons/view/video/FullPlayerView;", "full_player", "Landroidx/constraintlayout/widget/ConstraintLayout;", "rl_endPreview_price$delegate", "getRl_endPreview_price", "()Landroidx/constraintlayout/widget/ConstraintLayout;", "rl_endPreview_price", "Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_details$delegate", "getTablayout_details", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_details", "Landroid/widget/LinearLayout;", "ll_buy_limit_time$delegate", "getLl_buy_limit_time", "()Landroid/widget/LinearLayout;", "ll_buy_limit_time", "Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "mCommentFragment", "Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "getMCommentFragment", "()Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "setMCommentFragment", "(Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;)V", "Landroid/widget/FrameLayout;", "error_view$delegate", "getError_view", "()Landroid/widget/FrameLayout;", "error_view", "mVideoDetailBean", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "Landroid/widget/RelativeLayout;", "layout_error$delegate", "getLayout_error", "()Landroid/widget/RelativeLayout;", "layout_error", "tv_day$delegate", "getTv_day", "tv_day", "isCompletion", "Z", "layout_minutes_info$delegate", "getLayout_minutes_info", "layout_minutes_info", "Lcom/jbzd/media/movecartoons/view/ProgressButton;", "btn_retry$delegate", "getBtn_retry", "()Lcom/jbzd/media/movecartoons/view/ProgressButton;", "btn_retry", "Lc/a/d1;", "jobCountDown", "Lc/a/d1;", "Landroidx/viewpager/widget/ViewPager;", "vp_content_details$delegate", "getVp_content_details", "()Landroidx/viewpager/widget/ViewPager;", "vp_content_details", "tv_red_price$delegate", "getTv_red_price", "tv_red_price", "Landroid/widget/ImageView;", "iv_back$delegate", "getIv_back", "()Landroid/widget/ImageView;", "iv_back", "ll_endPreview_price$delegate", "getLl_endPreview_price", "ll_endPreview_price", "Landroid/util/ArrayMap;", "videoPlayHeader$delegate", "getVideoPlayHeader", "()Landroid/util/ArrayMap;", "videoPlayHeader", "rl_replay$delegate", "getRl_replay", "rl_replay", "tv_adTime$delegate", "getTv_adTime", "tv_adTime", "tv_red$delegate", "getTv_red", "tv_red", "ll_spinner$delegate", "getLl_spinner", "ll_spinner", "rl_videoBottomParent$delegate", "getRl_videoBottomParent", "rl_videoBottomParent", "layout_day_info$delegate", "getLayout_day_info", "layout_day_info", "tv_hour$delegate", "getTv_hour", "tv_hour", "Lcom/github/mmin18/widget/RealtimeBlurView;", "rbv_endPreview_price$delegate", "getRbv_endPreview_price", "()Lcom/github/mmin18/widget/RealtimeBlurView;", "rbv_endPreview_price", "tv_min$delegate", "getTv_min", "tv_min", "btn_recheck_line$delegate", "getBtn_recheck_line", "btn_recheck_line", "Lcom/youth/banner/Banner;", "playAd$delegate", "getPlayAd", "()Lcom/youth/banner/Banner;", "playAd", "layout_hour_info$delegate", "getLayout_hour_info", "layout_hour_info", "com/jbzd/media/movecartoons/ui/movie/MovieDetailsActivity$spinnerAdapter$2$1", "spinnerAdapter$delegate", "getSpinnerAdapter", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsActivity$spinnerAdapter$2$1;", "spinnerAdapter", "mSelectP", "I", "getMSelectP", "setMSelectP", "(I)V", "Landroid/os/CountDownTimer;", "timer", "Landroid/os/CountDownTimer;", "<init>", "Companion", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "tabEntities", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MovieDetailsActivity extends MyThemeViewModelActivity<MovieDetailsViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private boolean isCompletion;

    @Nullable
    private InterfaceC3053d1 jobCountDown;
    public CommentFragment mCommentFragment;

    @Nullable
    private String mId;
    private int mSelectP;

    @Nullable
    private VideoDetailBean mVideoDetailBean;

    @Nullable
    private PopupWindow popWindow;

    @Nullable
    private CountDownTimer timer;

    /* renamed from: mMovieDescFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mMovieDescFragment = LazyKt__LazyJVMKt.lazy(new Function0<MovieDescFragment>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$mMovieDescFragment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MovieDescFragment invoke() {
            MovieDescFragment.Companion companion = MovieDescFragment.INSTANCE;
            String stringExtra = MovieDetailsActivity.this.getIntent().getStringExtra("id");
            final MovieDetailsActivity movieDetailsActivity = MovieDetailsActivity.this;
            return companion.newInstance(stringExtra, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$mMovieDescFragment$2.1
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(String str) {
                    invoke2(str);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull String it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    MovieDetailsActivity.this.getViewModel().loadMovie(it, "");
                }
            });
        }
    });

    /* renamed from: videoPlayHeader$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy videoPlayHeader = LazyKt__LazyJVMKt.lazy(new Function0<ArrayMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$videoPlayHeader$2
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

    /* renamed from: ll_buy_limit_time$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_buy_limit_time = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$ll_buy_limit_time$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) MovieDetailsActivity.this.findViewById(R.id.ll_buy_limit_time);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: iv_back$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_back = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$iv_back$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) MovieDetailsActivity.this.findViewById(R.id.iv_back);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: full_player$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy full_player = LazyKt__LazyJVMKt.lazy(new Function0<FullPlayerView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$full_player$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FullPlayerView invoke() {
            FullPlayerView fullPlayerView = (FullPlayerView) MovieDetailsActivity.this.findViewById(R.id.full_player);
            Intrinsics.checkNotNull(fullPlayerView);
            return fullPlayerView;
        }
    });

    /* renamed from: layout_error$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_error = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$layout_error$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) MovieDetailsActivity.this.findViewById(R.id.layout_error);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: error_view$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy error_view = LazyKt__LazyJVMKt.lazy(new Function0<FrameLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$error_view$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FrameLayout invoke() {
            FrameLayout frameLayout = (FrameLayout) MovieDetailsActivity.this.findViewById(R.id.error_view);
            Intrinsics.checkNotNull(frameLayout);
            return frameLayout;
        }
    });

    /* renamed from: btn_retry$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_retry = LazyKt__LazyJVMKt.lazy(new Function0<ProgressButton>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$btn_retry$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ProgressButton invoke() {
            ProgressButton progressButton = (ProgressButton) MovieDetailsActivity.this.findViewById(R.id.btn_retry);
            Intrinsics.checkNotNull(progressButton);
            return progressButton;
        }
    });

    /* renamed from: btn_recheck_line$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_recheck_line = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$btn_recheck_line$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.btn_recheck_line);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: layout_day_info$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_day_info = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$layout_day_info$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) MovieDetailsActivity.this.findViewById(R.id.layout_day_info);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tv_day$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_day = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_day$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.tv_day);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: layout_hour_info$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_hour_info = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$layout_hour_info$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) MovieDetailsActivity.this.findViewById(R.id.layout_hour_info);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tv_hour$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_hour = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_hour$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.tv_hour);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: layout_minutes_info$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_minutes_info = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$layout_minutes_info$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) MovieDetailsActivity.this.findViewById(R.id.layout_minutes_info);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tv_min$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_min = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_min$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.tv_min);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_sec$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_sec = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_sec$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.tv_sec);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: rbv_endPreview_price$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rbv_endPreview_price = LazyKt__LazyJVMKt.lazy(new Function0<RealtimeBlurView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$rbv_endPreview_price$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RealtimeBlurView invoke() {
            RealtimeBlurView realtimeBlurView = (RealtimeBlurView) MovieDetailsActivity.this.findViewById(R.id.rbv_endPreview_price);
            Intrinsics.checkNotNull(realtimeBlurView);
            return realtimeBlurView;
        }
    });

    /* renamed from: ll_endPreview_price$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_endPreview_price = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$ll_endPreview_price$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) MovieDetailsActivity.this.findViewById(R.id.ll_endPreview_price);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: rl_endPreview_price$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rl_endPreview_price = LazyKt__LazyJVMKt.lazy(new Function0<ConstraintLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$rl_endPreview_price$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ConstraintLayout invoke() {
            ConstraintLayout constraintLayout = (ConstraintLayout) MovieDetailsActivity.this.findViewById(R.id.rl_endPreview_price);
            Intrinsics.checkNotNull(constraintLayout);
            return constraintLayout;
        }
    });

    /* renamed from: tv_red$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_red = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_red$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.tv_red);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_red_price$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_red_price = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_red_price$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.tv_red_price);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_adTime$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_adTime = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_adTime$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.tv_adTime);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: playAd$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy playAd = LazyKt__LazyJVMKt.lazy(new Function0<Banner<?, ?>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$playAd$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final Banner<?, ?> invoke() {
            Banner<?, ?> banner = (Banner) MovieDetailsActivity.this.findViewById(R.id.playAd);
            Intrinsics.checkNotNull(banner);
            return banner;
        }
    });

    /* renamed from: tv_spinner$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_spinner = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_spinner$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) MovieDetailsActivity.this.findViewById(R.id.tv_spinner);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: vp_content_details$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content_details = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$vp_content_details$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) MovieDetailsActivity.this.findViewById(R.id.vp_content_details);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tablayout_details$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tablayout_details = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tablayout_details$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) MovieDetailsActivity.this.findViewById(R.id.tablayout_details);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    /* renamed from: itv_replay$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_replay = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$itv_replay$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) MovieDetailsActivity.this.findViewById(R.id.itv_replay);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: rl_replay$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rl_replay = LazyKt__LazyJVMKt.lazy(new Function0<ConstraintLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$rl_replay$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ConstraintLayout invoke() {
            ConstraintLayout constraintLayout = (ConstraintLayout) MovieDetailsActivity.this.findViewById(R.id.rl_replay);
            Intrinsics.checkNotNull(constraintLayout);
            return constraintLayout;
        }
    });

    /* renamed from: tv_time_count_down$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_time_count_down = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$tv_time_count_down$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MovieDetailsActivity.this.findViewById(R.id.tv_time_count_down);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: ll_spinner$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_spinner = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$ll_spinner$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) MovieDetailsActivity.this.findViewById(R.id.ll_spinner);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: spinnerAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy spinnerAdapter = LazyKt__LazyJVMKt.lazy(new MovieDetailsActivity$spinnerAdapter$2(this));

    /* renamed from: rl_videoBottomParent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rl_videoBottomParent = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$rl_videoBottomParent$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) MovieDetailsActivity.this.findViewById(R.id.rl_videoBottomParent);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(MovieDetailsViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$special$$inlined$viewModels$default$1
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

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-1, reason: not valid java name */
    public static final void m5877bindEvent$lambda1(MovieDetailsActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.onBackPressed();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-11, reason: not valid java name */
    public static final void m5878bindEvent$lambda15$lambda11(final MovieDetailsActivity this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (!it.booleanValue()) {
            this$0.getLayout_error().setVisibility(8);
        } else {
            this$0.getLayout_error().setVisibility(0);
            this$0.getBtn_recheck_line().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.u
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    MovieDetailsActivity.m5879bindEvent$lambda15$lambda11$lambda10(MovieDetailsActivity.this, view);
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-11$lambda-10, reason: not valid java name */
    public static final void m5879bindEvent$lambda15$lambda11$lambda10(MovieDetailsActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getLayout_error().setVisibility(8);
        this$0.getViewModel().loadMovie(this$0.mId, "");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-12, reason: not valid java name */
    public static final void m5880bindEvent$lambda15$lambda12(MovieDetailsActivity this$0, Integer it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (Intrinsics.areEqual(C0843e0.m183b(it.intValue(), "day"), "0")) {
            this$0.getLayout_day_info().setVisibility(8);
        } else {
            this$0.getLayout_day_info().setVisibility(0);
            this$0.getTv_day().setText(C0843e0.m183b(it.intValue(), "day"));
        }
        if (Intrinsics.areEqual(C0843e0.m183b(it.intValue(), "hour"), "0")) {
            this$0.getLayout_hour_info().setVisibility(8);
        } else {
            this$0.getLayout_hour_info().setVisibility(0);
            this$0.getTv_hour().setText(C0843e0.m183b(it.intValue(), "hour"));
        }
        if (Intrinsics.areEqual(C0843e0.m183b(it.intValue(), "min"), "0")) {
            this$0.getLayout_minutes_info().setVisibility(8);
        } else {
            this$0.getLayout_minutes_info().setVisibility(0);
            this$0.getTv_min().setText(C0843e0.m183b(it.intValue(), "min"));
        }
        this$0.getTv_sec().setText(C0843e0.m183b(it.intValue(), "sec"));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-14, reason: not valid java name */
    public static final void m5881bindEvent$lambda15$lambda14(MovieDetailsViewModel this_run, MovieDetailsActivity this$0, String str) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        String value = this_run.getLinkIdMulti().getValue();
        if (value == null) {
            return;
        }
        this$0.getViewModel().loadMovie(this$0.mId, value);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-2, reason: not valid java name */
    public static final void m5882bindEvent$lambda15$lambda2(MovieDetailsActivity this$0, VideoDetailBean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.mVideoDetailBean = it;
        Intrinsics.checkNotNullExpressionValue(it, "it");
        this$0.initView(it);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-3, reason: not valid java name */
    public static final void m5883bindEvent$lambda15$lambda3(MovieDetailsActivity this$0, C2848a c2848a) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (c2848a.f7763a) {
            BaseActivity.showLoadingDialog$default(this$0, null, true, 1, null);
        } else {
            this$0.hideLoadingDialog();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-7, reason: not valid java name */
    public static final void m5884bindEvent$lambda15$lambda7(final MovieDetailsViewModel this_run, final MovieDetailsActivity this$0, String str) {
        String str2;
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this_run.getShowPlayError().setValue(Boolean.FALSE);
        final FullPlayerView full_player = this$0.getFull_player();
        full_player.playerImage.setVisibility(0);
        C2852c c2852c = (C2852c) ComponentCallbacks2C1553c.m739i(full_player);
        VideoDetailBean videoDetailBean = this$0.mVideoDetailBean;
        c2852c.m3298p(videoDetailBean == null ? null : videoDetailBean.img_x).m3295i0().m3294h0(true).m757R(full_player.mCoverImage);
        full_player.setBottomShow(true);
        if (this_run.getDetailInfo().getValue() == null) {
            return;
        }
        String str3 = str == null ? "" : str;
        ArrayMap<String, String> videoPlayHeader = this$0.getVideoPlayHeader();
        VideoDetailBean value = this$0.getViewModel().getDetailInfo().getValue();
        full_player.setUp(str3, true, (File) null, (Map<String, String>) videoPlayHeader, (value == null || (str2 = value.name) == null) ? "" : str2);
        Long value2 = this$0.getViewModel().getDuration().getValue();
        full_player.setSeekOnStart(value2 == null ? 0L : value2.longValue());
        full_player.setVideoAllCallBack(new MyVideoAllCallback() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$bindEvent$2$3$1$1$1
            @Override // com.jbzd.media.movecartoons.view.video.MyVideoAllCallback, p005b.p362y.p363a.p366f.InterfaceC2931g
            public void onPlayError(@Nullable String url, @NotNull Object... objects) {
                List<VideoDetailBean.PlayLinksBean> list;
                List<VideoDetailBean.PlayLinksBean> list2;
                Intrinsics.checkNotNullParameter(objects, "objects");
                String str4 = url == null ? "" : url;
                C0853j0 c0853j0 = C0853j0.f254c;
                C0851i0 c0851i0 = C0851i0.f252c;
                C0917a c0917a = C0917a.f372a;
                HashMap m596R = C1499a.m596R("type", "play_error", "data", str4);
                Unit unit = Unit.INSTANCE;
                C0917a.m221e(c0917a, "system/event", Object.class, m596R, c0853j0, c0851i0, false, false, null, false, 416);
                VideoDetailBean value3 = this_run.getDetailInfo().getValue();
                if (Intrinsics.areEqual(value3 == null ? null : value3.play_error_type, "none")) {
                    VideoDetailBean value4 = this_run.getDetailInfo().getValue();
                    if (value4 == null || (list2 = value4.play_links) == null) {
                        return;
                    }
                    MovieDetailsViewModel movieDetailsViewModel = this_run;
                    int i2 = 0;
                    for (Object obj : list2) {
                        int i3 = i2 + 1;
                        if (i2 < 0) {
                            CollectionsKt__CollectionsKt.throwIndexOverflow();
                        }
                        if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj).m3u8_url, url)) {
                            if (i2 == 0) {
                                MutableLiveData<String> linkCur = movieDetailsViewModel.getLinkCur();
                                VideoDetailBean value5 = movieDetailsViewModel.getDetailInfo().getValue();
                                List<VideoDetailBean.PlayLinksBean> list3 = value5 == null ? null : value5.play_links;
                                Intrinsics.checkNotNull(list3);
                                linkCur.setValue(list3.get(1).m3u8_url);
                                MutableLiveData<String> linkName = movieDetailsViewModel.getLinkName();
                                VideoDetailBean value6 = movieDetailsViewModel.getDetailInfo().getValue();
                                List<VideoDetailBean.PlayLinksBean> list4 = value6 == null ? null : value6.play_links;
                                Intrinsics.checkNotNull(list4);
                                linkName.setValue(list4.get(1).name);
                            } else {
                                MutableLiveData<String> linkCur2 = movieDetailsViewModel.getLinkCur();
                                VideoDetailBean value7 = movieDetailsViewModel.getDetailInfo().getValue();
                                List<VideoDetailBean.PlayLinksBean> list5 = value7 == null ? null : value7.play_links;
                                Intrinsics.checkNotNull(list5);
                                linkCur2.setValue(list5.get(0).m3u8_url);
                                MutableLiveData<String> linkName2 = movieDetailsViewModel.getLinkName();
                                VideoDetailBean value8 = movieDetailsViewModel.getDetailInfo().getValue();
                                List<VideoDetailBean.PlayLinksBean> list6 = value8 == null ? null : value8.play_links;
                                Intrinsics.checkNotNull(list6);
                                linkName2.setValue(list6.get(0).name);
                            }
                        }
                        i2 = i3;
                    }
                    return;
                }
                VideoDetailBean value9 = this_run.getDetailInfo().getValue();
                if (value9 == null || (list = value9.play_links) == null) {
                    return;
                }
                MovieDetailsViewModel movieDetailsViewModel2 = this_run;
                int i4 = 0;
                for (Object obj2 : list) {
                    int i5 = i4 + 1;
                    if (i4 < 0) {
                        CollectionsKt__CollectionsKt.throwIndexOverflow();
                    }
                    if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj2).preview_m3u8_url, url)) {
                        if (i4 == 0) {
                            MutableLiveData<String> linkCur3 = movieDetailsViewModel2.getLinkCur();
                            VideoDetailBean value10 = movieDetailsViewModel2.getDetailInfo().getValue();
                            List<VideoDetailBean.PlayLinksBean> list7 = value10 == null ? null : value10.play_links;
                            Intrinsics.checkNotNull(list7);
                            linkCur3.setValue(list7.get(1).preview_m3u8_url);
                            MutableLiveData<String> linkName3 = movieDetailsViewModel2.getLinkName();
                            VideoDetailBean value11 = movieDetailsViewModel2.getDetailInfo().getValue();
                            List<VideoDetailBean.PlayLinksBean> list8 = value11 == null ? null : value11.play_links;
                            Intrinsics.checkNotNull(list8);
                            linkName3.setValue(list8.get(1).name);
                        } else {
                            MutableLiveData<String> linkCur4 = movieDetailsViewModel2.getLinkCur();
                            VideoDetailBean value12 = movieDetailsViewModel2.getDetailInfo().getValue();
                            List<VideoDetailBean.PlayLinksBean> list9 = value12 == null ? null : value12.play_links;
                            Intrinsics.checkNotNull(list9);
                            linkCur4.setValue(list9.get(0).preview_m3u8_url);
                            MutableLiveData<String> linkName4 = movieDetailsViewModel2.getLinkName();
                            VideoDetailBean value13 = movieDetailsViewModel2.getDetailInfo().getValue();
                            List<VideoDetailBean.PlayLinksBean> list10 = value13 == null ? null : value13.play_links;
                            Intrinsics.checkNotNull(list10);
                            linkName4.setValue(list10.get(0).name);
                        }
                    }
                    i4 = i5;
                }
            }

            @Override // com.jbzd.media.movecartoons.view.video.MyVideoAllCallback, p005b.p362y.p363a.p366f.InterfaceC2931g
            public void onPrepared(@Nullable String url, @NotNull Object... objects) {
                Intrinsics.checkNotNullParameter(objects, "objects");
                if (MovieDetailsActivity.this.getLayout_error().getVisibility() == 0) {
                    MovieDetailsActivity.this.getLayout_error().setVisibility(8);
                }
            }
        });
        new Handler().postDelayed(new Runnable() { // from class: b.a.a.a.t.i.p
            @Override // java.lang.Runnable
            public final void run() {
                MovieDetailsActivity.m5885bindEvent$lambda15$lambda7$lambda6$lambda5$lambda4(FullPlayerView.this);
            }
        }, 500L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-7$lambda-6$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5885bindEvent$lambda15$lambda7$lambda6$lambda5$lambda4(FullPlayerView this_run) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this_run.startPlayLogic();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-9, reason: not valid java name */
    public static final void m5886bindEvent$lambda15$lambda9(final MovieDetailsActivity this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (it.booleanValue()) {
            this$0.getError_view().setVisibility(0);
            this$0.getBtn_retry().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.z
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    MovieDetailsActivity.m5887bindEvent$lambda15$lambda9$lambda8(MovieDetailsActivity.this, view);
                }
            });
        } else {
            this$0.getError_view().setVisibility(8);
            this$0.getBtn_retry().setProgress(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-15$lambda-9$lambda-8, reason: not valid java name */
    public static final void m5887bindEvent$lambda15$lambda9$lambda8(MovieDetailsActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getViewModel().loadMovie(this$0.mId, "");
    }

    private final void bindPreviewPriceCover(boolean show) {
        getRbv_endPreview_price().setVisibility(show ^ true ? 0 : 8);
        getLl_endPreview_price().setVisibility(show ^ true ? 0 : 8);
    }

    private final void bindPriceCover(final VideoDetailBean video, boolean isPreviewVideo) {
        getRl_endPreview_price().setVisibility(0);
        getTv_red().setVisibility(0);
        getTv_red().setText(video.play_error);
        getTv_red_price().setText(Intrinsics.stringPlus(video.money, "金币解锁 观看完整版"));
        getTv_red().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.t
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MovieDetailsActivity.m5888bindPriceCover$lambda17$lambda16(MovieDetailsActivity.this, video, view);
            }
        });
        bindPreviewPriceCover(isPreviewVideo);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindPriceCover$lambda-17$lambda-16, reason: not valid java name */
    public static final void m5888bindPriceCover$lambda17$lambda16(MovieDetailsActivity this$0, VideoDetailBean video, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(video, "$video");
        this$0.priceDialog(video, false);
    }

    private final void countDown(int time, String jump) {
        cancelJob(this.jobCountDown);
        getTv_adTime().setText(time + " 秒");
        getTv_adTime().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.s
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MovieDetailsActivity.m5889countDown$lambda18(MovieDetailsActivity.this, view);
            }
        });
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        this.jobCountDown = C2354n.m2435U0(c3109w0, C2964m.f8127b, 0, new MovieDetailsActivity$countDown$2(time, jump, this, null), 2, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: countDown$lambda-18, reason: not valid java name */
    public static final void m5889countDown$lambda18(MovieDetailsActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (Intrinsics.areEqual(this$0.getTv_adTime().getText(), "播放")) {
            this$0.getFull_player().setVisibility(0);
            this$0.getPlayAd().setVisibility(8);
            this$0.getTv_adTime().setVisibility(8);
            this$0.getViewModel().updateLine();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void doBuyVideo(final VideoDetailBean video) {
        INSTANCE.checkMoneyForBuyVideo(video, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$doBuyVideo$1
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
                if (!z) {
                    RechargeActivity.INSTANCE.start(MovieDetailsActivity.this);
                    return;
                }
                MovieDetailsViewModel viewModel = MovieDetailsActivity.this.getViewModel();
                String str = video.f10000id;
                Intrinsics.checkNotNullExpressionValue(str, "video.id");
                viewModel.doBuyMovie(str, true);
            }
        });
    }

    private final void getCountDownTime(final long counts) {
        new CountDownTimer(counts) { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$getCountDownTime$1
            public final /* synthetic */ long $counts;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(counts, 1000L);
                this.$counts = counts;
            }

            @Override // android.os.CountDownTimer
            public void onFinish() {
            }

            @Override // android.os.CountDownTimer
            public void onTick(long endtimes) {
            }
        }.start();
    }

    private final MovieDescFragment getMMovieDescFragment() {
        return (MovieDescFragment) this.mMovieDescFragment.getValue();
    }

    private final MovieDetailsActivity$spinnerAdapter$2.C38301 getSpinnerAdapter() {
        return (MovieDetailsActivity$spinnerAdapter$2.C38301) this.spinnerAdapter.getValue();
    }

    private final ArrayMap<String, String> getVideoPlayHeader() {
        return (ArrayMap) this.videoPlayHeader.getValue();
    }

    private final void initPlay() {
        final FullPlayerView full_player = getFull_player();
        full_player.setOnCompletionListener(new FullPlayerView.OnCompletionListener() { // from class: b.a.a.a.t.i.c0
            @Override // com.jbzd.media.movecartoons.view.video.FullPlayerView.OnCompletionListener
            public final void onCompletion() {
                MovieDetailsActivity.m5890initPlay$lambda38$lambda35(MovieDetailsActivity.this);
            }
        });
        full_player.setHideTopLayoutWhenSmall(Boolean.TRUE);
        full_player.setShowFullAnimation(false);
        full_player.setNeedLockFull(true);
        full_player.setAutoFullWithSize(true);
        full_player.setLooping(false);
        full_player.getFullscreenButton().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.y
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MovieDetailsActivity.m5891initPlay$lambda38$lambda36(MovieDetailsActivity.this, full_player, view);
            }
        });
        full_player.setGSYVideoProgressListener(new InterfaceC2927c() { // from class: b.a.a.a.t.i.i0
            @Override // p005b.p362y.p363a.p366f.InterfaceC2927c
            /* renamed from: a */
            public final void mo301a(int i2, int i3, int i4, int i5) {
                MovieDetailsActivity.m5892initPlay$lambda38$lambda37(MovieDetailsActivity.this, i2, i3, i4, i5);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initPlay$lambda-38$lambda-35, reason: not valid java name */
    public static final void m5890initPlay$lambda38$lambda35(MovieDetailsActivity this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.isCompletion = true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initPlay$lambda-38$lambda-36, reason: not valid java name */
    public static final void m5891initPlay$lambda38$lambda36(MovieDetailsActivity this$0, FullPlayerView this_run, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this$0.getFull_player().startWindowFullscreen(this_run.getContext(), false, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initPlay$lambda-38$lambda-37, reason: not valid java name */
    public static final void m5892initPlay$lambda38$lambda37(MovieDetailsActivity this$0, int i2, int i3, int i4, int i5) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getViewModel().getDuration().postValue(Long.valueOf(i4));
    }

    @SuppressLint({"ClickableViewAccessibility", "UseCompatLoadingForDrawables"})
    private final void initSpinner(List<? extends VideoDetailBean.PlayLinksBean> links, String link_name) {
        View inflate = LayoutInflater.from(this).inflate(R.layout.item_pop, (ViewGroup) null, false);
        Intrinsics.checkNotNullExpressionValue(inflate, "from(this@MovieDetailsActivity).inflate(R.layout.item_pop, null, false)");
        RecyclerView recyclerView = (RecyclerView) inflate.findViewById(R.id.rv_spinner);
        ((TextView) inflate.findViewById(R.id.tv_cancel_chooseline)).setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.q
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MovieDetailsActivity.m5893initSpinner$lambda31(MovieDetailsActivity.this, view);
            }
        });
        RecyclerView.ItemDecoration itemDecoration = getItemDecoration();
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
        recyclerView.setLayoutManager(new LinearLayoutManager(this, 1, false));
        recyclerView.setAdapter(getSpinnerAdapter());
        if (itemDecoration != null) {
            recyclerView.addItemDecoration(itemDecoration);
        }
        PopupWindow popupWindow = new PopupWindow(inflate, -1, -1, true);
        this.popWindow = popupWindow;
        if (popupWindow == null) {
            return;
        }
        popupWindow.setAnimationStyle(R.anim.push_bottom_in);
        popupWindow.setTouchable(true);
        popupWindow.setTouchInterceptor(new View.OnTouchListener() { // from class: b.a.a.a.t.i.v
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                boolean m5894initSpinner$lambda34$lambda33;
                m5894initSpinner$lambda34$lambda33 = MovieDetailsActivity.m5894initSpinner$lambda34$lambda33(view, motionEvent);
                return m5894initSpinner$lambda34$lambda33;
            }
        });
        popupWindow.setBackgroundDrawable(getResources().getDrawable(R.color.transparent_nearn));
        popupWindow.showAtLocation(getRl_videoBottomParent(), 80, 0, 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initSpinner$lambda-31, reason: not valid java name */
    public static final void m5893initSpinner$lambda31(MovieDetailsActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        PopupWindow popupWindow = this$0.popWindow;
        if (popupWindow == null) {
            return;
        }
        popupWindow.dismiss();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initSpinner$lambda-34$lambda-33, reason: not valid java name */
    public static final boolean m5894initSpinner$lambda34$lambda33(View view, MotionEvent motionEvent) {
        return false;
    }

    private final void initView(final VideoDetailBean video) {
        if (video != null) {
            if (video.play_ads != null) {
                getPlayAd().setVisibility(0);
                getTv_adTime().setVisibility(0);
                String str = video.play_ad_show_time;
                Intrinsics.checkNotNullExpressionValue(str, "video.play_ad_show_time");
                int parseInt = Integer.parseInt(str);
                String str2 = video.play_ad_auto_jump;
                Intrinsics.checkNotNullExpressionValue(str2, "video.play_ad_auto_jump");
                countDown(parseInt, str2);
                final Banner<?, ?> playAd = getPlayAd();
                playAd.setIntercept(video.play_ads.size() != 1);
                Banner addBannerLifecycleObserver = playAd.addBannerLifecycleObserver(this);
                Context context = playAd.getContext();
                Intrinsics.checkNotNullExpressionValue(context, "context");
                List<AdBean> list = video.play_ads;
                Intrinsics.checkNotNullExpressionValue(list, "video.play_ads");
                ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(list, 10));
                Iterator<T> it = list.iterator();
                while (it.hasNext()) {
                    arrayList.add(((AdBean) it.next()).content);
                }
                addBannerLifecycleObserver.setAdapter(new BannerAdapterImp(context, arrayList, 0.0f, ShadowDrawableWrapper.COS_45, ImageView.ScaleType.CENTER_CROP, 4));
                playAd.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.i.w
                    @Override // com.youth.banner.listener.OnBannerListener
                    public final void OnBannerClick(Object obj, int i2) {
                        MovieDetailsActivity.m5895initView$lambda21$lambda20(Banner.this, video, obj, i2);
                    }
                });
                playAd.setIndicator(new RectangleIndicator(playAd.getContext()));
                playAd.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$initView$1$3
                    @Override // com.youth.banner.listener.OnPageChangeListener
                    public void onPageScrollStateChanged(int state) {
                    }

                    @Override // com.youth.banner.listener.OnPageChangeListener
                    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                    }

                    @Override // com.youth.banner.listener.OnPageChangeListener
                    public void onPageSelected(int position) {
                    }
                });
                playAd.start();
            } else {
                getFull_player().setVisibility(0);
                getViewModel().updateLine();
            }
            MovieDescFragment.Companion companion = MovieDescFragment.INSTANCE;
            companion.setMVideoDetailBean(video);
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
            if (Intrinsics.areEqual(string, "")) {
                getTv_spinner().setText(companion.getMVideoDetailBean().play_links.get(0).name);
            } else {
                List<VideoDetailBean.PlayLinksBean> list2 = companion.getMVideoDetailBean().play_links;
                Intrinsics.checkNotNullExpressionValue(list2, "MovieDescFragment.mVideoDetailBean.play_links");
                int i2 = 0;
                for (Object obj : list2) {
                    int i3 = i2 + 1;
                    if (i2 < 0) {
                        CollectionsKt__CollectionsKt.throwIndexOverflow();
                    }
                    String str3 = ((VideoDetailBean.PlayLinksBean) obj).f9995id;
                    Intrinsics.checkNotNullParameter("default_line", "key");
                    Intrinsics.checkNotNullParameter("", "default");
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
                        getTv_spinner().setText(MovieDescFragment.INSTANCE.getMVideoDetailBean().play_links.get(i2).name);
                    }
                    i2 = i3;
                }
            }
        }
        CommentFragment.Companion companion2 = CommentFragment.INSTANCE;
        String str4 = video.f10000id;
        Intrinsics.checkNotNullExpressionValue(str4, "video.id");
        setMCommentFragment(companion2.newInstance(str4, "movie"));
        ArrayList arrayList2 = new ArrayList();
        arrayList2.add(getMMovieDescFragment());
        arrayList2.add(getMCommentFragment());
        FragmentManager supportFragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
        ViewPagerAdapter viewPagerAdapter = new ViewPagerAdapter(supportFragmentManager, arrayList2, 0, 4, null);
        Lazy lazy = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$initView$tabEntities$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ArrayList<String> invoke() {
                StringBuilder m586H = C1499a.m586H("评论(");
                m586H.append((Object) VideoDetailBean.this.comment);
                m586H.append(')');
                return CollectionsKt__CollectionsKt.arrayListOf("详情", m586H.toString());
            }
        });
        ViewPager vp_content_details = getVp_content_details();
        vp_content_details.setOffscreenPageLimit(m5896initView$lambda23(lazy).size());
        vp_content_details.setAdapter(viewPagerAdapter);
        vp_content_details.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$initView$3$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
            }
        });
        SlidingTabLayout tablayout_details = getTablayout_details();
        ViewPager vp_content_details2 = getVp_content_details();
        Object[] array = m5896initView$lambda23(lazy).toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tablayout_details.m4011e(vp_content_details2, (String[]) array);
        if (!m5896initView$lambda23(lazy).isEmpty()) {
            getVp_content_details().setCurrentItem(0);
        }
        if (Intrinsics.areEqual(video.play_error_type, "need_vip") || Intrinsics.areEqual(video.play_error_type, "need_buy")) {
            bindPriceCover(video, true);
            getFull_player().setCallBack(new FullPlayerView.VideoCallBack() { // from class: b.a.a.a.t.i.x
                @Override // com.jbzd.media.movecartoons.view.video.FullPlayerView.VideoCallBack
                public final void onAutoComplete() {
                    MovieDetailsActivity.m5897initView$lambda26(MovieDetailsActivity.this, video);
                }
            });
        } else {
            getRl_endPreview_price().setVisibility(8);
        }
        getItv_replay().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.l
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MovieDetailsActivity.m5898initView$lambda27(MovieDetailsActivity.this, view);
            }
        });
        getLl_buy_limit_time().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.m
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MovieDetailsActivity.m5899initView$lambda28(MovieDetailsActivity.this, view);
            }
        });
        int i4 = video.upgrade_vip_countdown;
        if (i4 < 0) {
            getCountDownTime(i4);
        }
        if (video.upgrade_vip_countdown > 0) {
            getLl_buy_limit_time().setVisibility(0);
            getTv_time_count_down().setText(video.upgrade_vip_tips);
        } else {
            getLl_buy_limit_time().setVisibility(8);
        }
        getLl_spinner().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.f0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MovieDetailsActivity.m5900initView$lambda29(MovieDetailsActivity.this, video, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initView$lambda-21$lambda-20, reason: not valid java name */
    public static final void m5895initView$lambda21$lambda20(Banner this_run, VideoDetailBean video, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(video, "$video");
        C0840d.a aVar = C0840d.f235a;
        Context context = this_run.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        AdBean adBean = video.play_ads.get(i2);
        Intrinsics.checkNotNullExpressionValue(adBean, "video.play_ads[position]");
        aVar.m176b(context, adBean);
    }

    /* renamed from: initView$lambda-23, reason: not valid java name */
    private static final ArrayList<String> m5896initView$lambda23(Lazy<? extends ArrayList<String>> lazy) {
        return lazy.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initView$lambda-26, reason: not valid java name */
    public static final void m5897initView$lambda26(MovieDetailsActivity this$0, VideoDetailBean video) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(video, "$video");
        this$0.priceDialog(video, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initView$lambda-27, reason: not valid java name */
    public static final void m5898initView$lambda27(MovieDetailsActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getRl_replay().setVisibility(8);
        this$0.getFull_player().startPlayLogic();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initView$lambda-28, reason: not valid java name */
    public static final void m5899initView$lambda28(MovieDetailsActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        BuyActivity.INSTANCE.start(this$0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initView$lambda-29, reason: not valid java name */
    public static final void m5900initView$lambda29(MovieDetailsActivity this$0, VideoDetailBean video, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(video, "$video");
        List<VideoDetailBean.PlayLinksBean> list = video.play_links;
        Intrinsics.checkNotNullExpressionValue(list, "video.play_links");
        this$0.initSpinner(list, this$0.getTv_spinner().getText().toString());
    }

    private final void priceDialog(final VideoDetailBean video, boolean isPreviewEnd) {
        Object obj;
        String str = isPreviewEnd ? "试看结束" : "温馨提示";
        String str2 = video.play_error;
        Intrinsics.checkNotNullExpressionValue(str2, "video.play_error");
        String str3 = video.play_error_type;
        Intrinsics.checkNotNullExpressionValue(str3, "video.play_error_type");
        StringBuilder sb = new StringBuilder();
        sb.append("当前余额：");
        MyApp myApp = MyApp.f9891f;
        UserInfoBean userInfoBean = MyApp.f9892g;
        if (userInfoBean == null || (obj = userInfoBean.balance) == null) {
            obj = 0;
        }
        sb.append(obj);
        sb.append("金币");
        new UpgradePriceDialog(isPreviewEnd, str, str2, str3, sb.toString(), Intrinsics.stringPlus(video.money, "金币解锁"), new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$priceDialog$1
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
                MovieDetailsActivity.this.doBuyVideo(video);
            }
        }).show(getSupportFragmentManager(), "vipDialog");
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getLl_buy_limit_time().setVisibility(8);
        getIv_back().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.i.b0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MovieDetailsActivity.m5877bindEvent$lambda1(MovieDetailsActivity.this, view);
            }
        });
        initPlay();
        final MovieDetailsViewModel viewModel = getViewModel();
        viewModel.getDetailInfo().observe(this, new Observer() { // from class: b.a.a.a.t.i.r
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDetailsActivity.m5882bindEvent$lambda15$lambda2(MovieDetailsActivity.this, (VideoDetailBean) obj);
            }
        });
        viewModel.getLoading().observe(this, new Observer() { // from class: b.a.a.a.t.i.g0
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDetailsActivity.m5883bindEvent$lambda15$lambda3(MovieDetailsActivity.this, (C2848a) obj);
            }
        });
        viewModel.getLinkCur().observe(this, new Observer() { // from class: b.a.a.a.t.i.h0
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDetailsActivity.m5884bindEvent$lambda15$lambda7(MovieDetailsViewModel.this, this, (String) obj);
            }
        });
        viewModel.getShowError().observe(this, new Observer() { // from class: b.a.a.a.t.i.n
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDetailsActivity.m5886bindEvent$lambda15$lambda9(MovieDetailsActivity.this, (Boolean) obj);
            }
        });
        viewModel.getShowPlayError().observe(this, new Observer() { // from class: b.a.a.a.t.i.d0
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDetailsActivity.m5878bindEvent$lambda15$lambda11(MovieDetailsActivity.this, (Boolean) obj);
            }
        });
        viewModel.getCountdown().observe(this, new Observer() { // from class: b.a.a.a.t.i.o
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDetailsActivity.m5880bindEvent$lambda15$lambda12(MovieDetailsActivity.this, (Integer) obj);
            }
        });
        viewModel.getLinkIdMulti().observe(this, new Observer() { // from class: b.a.a.a.t.i.a0
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDetailsActivity.m5881bindEvent$lambda15$lambda14(MovieDetailsViewModel.this, this, (String) obj);
            }
        });
    }

    @NotNull
    public final TextView getBtn_recheck_line() {
        return (TextView) this.btn_recheck_line.getValue();
    }

    @NotNull
    public final ProgressButton getBtn_retry() {
        return (ProgressButton) this.btn_retry.getValue();
    }

    @NotNull
    public final FrameLayout getError_view() {
        return (FrameLayout) this.error_view.getValue();
    }

    @NotNull
    public final FullPlayerView getFull_player() {
        return (FullPlayerView) this.full_player.getValue();
    }

    @NotNull
    public final RecyclerView.ItemDecoration getItemDecoration() {
        XDividerItemDecoration xDividerItemDecoration = new XDividerItemDecoration(this, 1);
        xDividerItemDecoration.setDrawable(getResources().getDrawable(R.drawable.divider_line));
        return xDividerItemDecoration;
    }

    @NotNull
    public final ImageTextView getItv_replay() {
        return (ImageTextView) this.itv_replay.getValue();
    }

    @NotNull
    public final ImageView getIv_back() {
        return (ImageView) this.iv_back.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_movie_details;
    }

    @NotNull
    public final LinearLayout getLayout_day_info() {
        return (LinearLayout) this.layout_day_info.getValue();
    }

    @NotNull
    public final RelativeLayout getLayout_error() {
        return (RelativeLayout) this.layout_error.getValue();
    }

    @NotNull
    public final LinearLayout getLayout_hour_info() {
        return (LinearLayout) this.layout_hour_info.getValue();
    }

    @NotNull
    public final LinearLayout getLayout_minutes_info() {
        return (LinearLayout) this.layout_minutes_info.getValue();
    }

    @NotNull
    public final LinearLayout getLl_buy_limit_time() {
        return (LinearLayout) this.ll_buy_limit_time.getValue();
    }

    @NotNull
    public final LinearLayout getLl_endPreview_price() {
        return (LinearLayout) this.ll_endPreview_price.getValue();
    }

    @NotNull
    public final LinearLayout getLl_spinner() {
        return (LinearLayout) this.ll_spinner.getValue();
    }

    @NotNull
    public final CommentFragment getMCommentFragment() {
        CommentFragment commentFragment = this.mCommentFragment;
        if (commentFragment != null) {
            return commentFragment;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mCommentFragment");
        throw null;
    }

    public final int getMSelectP() {
        return this.mSelectP;
    }

    @NotNull
    public final Banner<?, ?> getPlayAd() {
        return (Banner) this.playAd.getValue();
    }

    @NotNull
    public final RealtimeBlurView getRbv_endPreview_price() {
        return (RealtimeBlurView) this.rbv_endPreview_price.getValue();
    }

    @NotNull
    public final ConstraintLayout getRl_endPreview_price() {
        return (ConstraintLayout) this.rl_endPreview_price.getValue();
    }

    @NotNull
    public final ConstraintLayout getRl_replay() {
        return (ConstraintLayout) this.rl_replay.getValue();
    }

    @NotNull
    public final LinearLayout getRl_videoBottomParent() {
        return (LinearLayout) this.rl_videoBottomParent.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTablayout_details() {
        return (SlidingTabLayout) this.tablayout_details.getValue();
    }

    @NotNull
    public final TextView getTv_adTime() {
        return (TextView) this.tv_adTime.getValue();
    }

    @NotNull
    public final TextView getTv_day() {
        return (TextView) this.tv_day.getValue();
    }

    @NotNull
    public final TextView getTv_hour() {
        return (TextView) this.tv_hour.getValue();
    }

    @NotNull
    public final TextView getTv_min() {
        return (TextView) this.tv_min.getValue();
    }

    @NotNull
    public final TextView getTv_red() {
        return (TextView) this.tv_red.getValue();
    }

    @NotNull
    public final TextView getTv_red_price() {
        return (TextView) this.tv_red_price.getValue();
    }

    @NotNull
    public final TextView getTv_sec() {
        return (TextView) this.tv_sec.getValue();
    }

    @NotNull
    public final ImageTextView getTv_spinner() {
        return (ImageTextView) this.tv_spinner.getValue();
    }

    @NotNull
    public final TextView getTv_time_count_down() {
        return (TextView) this.tv_time_count_down.getValue();
    }

    @NotNull
    public MovieDetailsViewModel getViewModel() {
        return (MovieDetailsViewModel) this.viewModel.getValue();
    }

    @NotNull
    public final ViewPager getVp_content_details() {
        return (ViewPager) this.vp_content_details.getValue();
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (C2920c.m3393b(this)) {
            return;
        }
        super.onBackPressed();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        String stringExtra = getIntent().getStringExtra("id");
        this.mId = stringExtra;
        if (stringExtra == null || stringExtra.length() == 0) {
            onBackPressed();
        }
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.jobCountDown);
        C2920c.m3397f();
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onNewIntent(@Nullable Intent intent) {
        super.onNewIntent(intent);
        getViewModel().addHistory(this.mId);
        this.mId = intent == null ? null : intent.getStringExtra("id");
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        super.onPause();
        C2920c.m3395d();
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        getViewModel().loadMovie(this.mId, "");
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onStop() {
        super.onStop();
        getViewModel().addHistory(this.mId);
    }

    public final void setMCommentFragment(@NotNull CommentFragment commentFragment) {
        Intrinsics.checkNotNullParameter(commentFragment, "<set-?>");
        this.mCommentFragment = commentFragment;
    }

    public final void setMSelectP(int i2) {
        this.mSelectP = i2;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public MovieDetailsViewModel viewModelInstance() {
        return getViewModel();
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0016\u0010\u0017J)\u0010\t\u001a\u00020\b2\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\b\u0010\u0007\u001a\u0004\u0018\u00010\u0006¢\u0006\u0004\b\t\u0010\nJ\u001f\u0010\t\u001a\u00020\b2\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u0004¢\u0006\u0004\b\t\u0010\u000bJ:\u0010\u0014\u001a\u00020\b2\u0006\u0010\r\u001a\u00020\f2#\b\u0002\u0010\u0013\u001a\u001d\u0012\u0013\u0012\u00110\u000f¢\u0006\f\b\u0010\u0012\b\b\u0011\u0012\u0004\b\b(\u0012\u0012\u0004\u0012\u00020\b0\u000e¢\u0006\u0004\b\u0014\u0010\u0015¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsActivity$Companion;", "", "Landroid/content/Context;", "context", "", "id", "", "bg", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/Integer;)V", "(Landroid/content/Context;Ljava/lang/String;)V", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "video", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "isBalanceEnough", "result", "checkMoneyForBuyVideo", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;Lkotlin/jvm/functions/Function1;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ void checkMoneyForBuyVideo$default(Companion companion, VideoDetailBean videoDetailBean, Function1 function1, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                function1 = new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$Companion$checkMoneyForBuyVideo$1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                    }
                };
            }
            companion.checkMoneyForBuyVideo(videoDetailBean, function1);
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
        public final void checkMoneyForBuyVideo(@org.jetbrains.annotations.NotNull com.jbzd.media.movecartoons.bean.response.VideoDetailBean r5, @org.jetbrains.annotations.NotNull kotlin.jvm.functions.Function1<? super java.lang.Boolean, kotlin.Unit> r6) {
            /*
                r4 = this;
                java.lang.String r0 = "video"
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
            throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity.Companion.checkMoneyForBuyVideo(com.jbzd.media.movecartoons.bean.response.VideoDetailBean, kotlin.jvm.functions.Function1):void");
        }

        public final void start(@NotNull Context context, @Nullable String id, @Nullable Integer bg) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) MovieDetailsActivity.class);
            intent.putExtra("id", id);
            intent.putExtra("bg", bg);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }

        public final void start(@NotNull Context context, @Nullable String id) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) MovieDetailsActivity.class);
            intent.putExtra("id", id);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }
}

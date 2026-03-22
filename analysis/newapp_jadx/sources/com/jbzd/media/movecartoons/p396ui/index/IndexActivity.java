package com.jbzd.media.movecartoons.p396ui.index;

import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Process;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.View;
import android.view.animation.LinearInterpolator;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioGroup;
import androidx.activity.ComponentActivity;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.constraintlayout.motion.widget.Key;
import androidx.core.app.ActivityCompat;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.LifecycleOwnerKt;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.viewpager.widget.ViewPager;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.event.EventChangeTab;
import com.jbzd.media.movecartoons.bean.response.TypeAdBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.ActivityReminderDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.NoticeDialog;
import com.jbzd.media.movecartoons.p396ui.index.BottomTab;
import com.jbzd.media.movecartoons.p396ui.index.IndexActivity;
import com.jbzd.media.movecartoons.p396ui.index.found.FoundFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.AiAreaFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeBCYFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeFragment;
import com.jbzd.media.movecartoons.p396ui.index.post.PostHomeFragment;
import com.jbzd.media.movecartoons.p396ui.mine.MineFragment;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.p396ui.novel.AudioPlayerActivity;
import com.jbzd.media.movecartoons.p396ui.novel.PlayModeFragment;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.NoScrollViewPager;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.MyRadioButton;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.service.ServerManager;
import com.qunidayede.supportlibrary.core.view.BaseFragment;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
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
import kotlin.jvm.internal.Ref;
import kotlin.jvm.internal.Reflection;
import kotlin.jvm.internal.TypeIntrinsics;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0846g;
import p005b.p006a.p007a.p008a.p009a.C0876x;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p006a.p007a.p008a.p023s.C0959d0;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.p150t.AbstractC1643k;
import p005b.p143g.p144a.p166q.C1777d;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p143g.p144a.p170s.C1802d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p336c.C2852c;
import p426f.p427a.p428a.C4325a;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Ì\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\t\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0017\u0018\u0000 ¯\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002¯\u0001B\b¢\u0006\u0005\b®\u0001\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0017\u0010\b\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\n\u0010\u0005J\u000f\u0010\u000b\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u000b\u0010\u0005J\u0017\u0010\u000e\u001a\u00020\u00032\u0006\u0010\r\u001a\u00020\fH\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ!\u0010\u0013\u001a\u00020\u00032\u0006\u0010\u0011\u001a\u00020\u00102\b\u0010\u0012\u001a\u0004\u0018\u00010\fH\u0002¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0015\u0010\u0005J\u0017\u0010\u0018\u001a\u00020\u00032\u0006\u0010\u0017\u001a\u00020\u0016H\u0002¢\u0006\u0004\b\u0018\u0010\u0019J'\u0010\u001d\u001a\u00020\u00032\u000e\u0010\u001b\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\u001a2\u0006\u0010\u001c\u001a\u00020\fH\u0002¢\u0006\u0004\b\u001d\u0010\u001eJ\u0019\u0010 \u001a\u0004\u0018\u00010\u00102\u0006\u0010\u001f\u001a\u00020\u0016H\u0002¢\u0006\u0004\b \u0010!J\u0019\u0010$\u001a\u0004\u0018\u00010#2\u0006\u0010\"\u001a\u00020\u0016H\u0002¢\u0006\u0004\b$\u0010%J\u000f\u0010'\u001a\u00020&H\u0002¢\u0006\u0004\b'\u0010(J\u000f\u0010)\u001a\u00020\u0003H\u0002¢\u0006\u0004\b)\u0010\u0005J\u0019\u0010,\u001a\u00020\u00032\b\u0010+\u001a\u0004\u0018\u00010*H\u0014¢\u0006\u0004\b,\u0010-J\u0017\u0010/\u001a\u00020\u00032\u0006\u0010.\u001a\u00020\u0006H\u0007¢\u0006\u0004\b/\u0010\tJ\u000f\u00100\u001a\u00020\u0003H\u0014¢\u0006\u0004\b0\u0010\u0005J\u0019\u00103\u001a\u00020\u00032\b\u00102\u001a\u0004\u0018\u000101H\u0014¢\u0006\u0004\b3\u00104J\u000f\u00105\u001a\u00020\u0002H\u0016¢\u0006\u0004\b5\u00106J\u000f\u00107\u001a\u00020\u0003H\u0014¢\u0006\u0004\b7\u0010\u0005J\r\u00103\u001a\u00020\u0003¢\u0006\u0004\b3\u0010\u0005J\u000f\u00108\u001a\u00020\u0003H\u0014¢\u0006\u0004\b8\u0010\u0005J\u000f\u00109\u001a\u00020\u0003H\u0016¢\u0006\u0004\b9\u0010\u0005J\u000f\u0010:\u001a\u00020\u0016H\u0016¢\u0006\u0004\b:\u0010;J!\u0010?\u001a\u00020&2\u0006\u0010<\u001a\u00020\u00162\b\u0010>\u001a\u0004\u0018\u00010=H\u0016¢\u0006\u0004\b?\u0010@J\r\u0010A\u001a\u00020\u0003¢\u0006\u0004\bA\u0010\u0005J)\u0010E\u001a\u00020\u00032\u0006\u0010B\u001a\u00020\u00162\u0006\u0010C\u001a\u00020\u00162\b\u0010D\u001a\u0004\u0018\u00010*H\u0014¢\u0006\u0004\bE\u0010FR\u001d\u0010L\u001a\u00020G8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bH\u0010I\u001a\u0004\bJ\u0010KR\u001d\u0010Q\u001a\u00020M8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bN\u0010I\u001a\u0004\bO\u0010PR\u001d\u0010V\u001a\u00020R8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bS\u0010I\u001a\u0004\bT\u0010UR*\u0010W\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\u001a8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bW\u0010X\u001a\u0004\bY\u0010Z\"\u0004\b[\u0010\\R\u001d\u0010_\u001a\u00020G8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010I\u001a\u0004\b^\u0010KR\u001d\u0010d\u001a\u00020`8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\ba\u0010I\u001a\u0004\bb\u0010cR\u001d\u0010i\u001a\u00020e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bf\u0010I\u001a\u0004\bg\u0010hR\u001d\u0010l\u001a\u00020G8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bj\u0010I\u001a\u0004\bk\u0010KR\u001d\u0010o\u001a\u00020G8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bm\u0010I\u001a\u0004\bn\u0010KR\u001d\u0010r\u001a\u00020G8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bp\u0010I\u001a\u0004\bq\u0010KR-\u0010y\u001a\u0012\u0012\u0004\u0012\u00020t0sj\b\u0012\u0004\u0012\u00020t`u8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bv\u0010I\u001a\u0004\bw\u0010xR%\u0010{\u001a\u0004\u0018\u00010z8\u0006@\u0006X\u0086\u000e¢\u0006\u0013\n\u0004\b{\u0010|\u001a\u0004\b}\u0010~\"\u0005\b\u007f\u0010\u0080\u0001R\u001a\u0010\u0082\u0001\u001a\u00030\u0081\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\b\u0082\u0001\u0010\u0083\u0001R \u0010\u0086\u0001\u001a\u00020G8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0084\u0001\u0010I\u001a\u0005\b\u0085\u0001\u0010KR\"\u0010\u008b\u0001\u001a\u00030\u0087\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0088\u0001\u0010I\u001a\u0006\b\u0089\u0001\u0010\u008a\u0001R\"\u0010\u0090\u0001\u001a\u00030\u008c\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u008d\u0001\u0010I\u001a\u0006\b\u008e\u0001\u0010\u008f\u0001R\"\u0010\u0095\u0001\u001a\u00030\u0091\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0092\u0001\u0010I\u001a\u0006\b\u0093\u0001\u0010\u0094\u0001R\"\u0010\u0098\u0001\u001a\u00030\u0091\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0096\u0001\u0010I\u001a\u0006\b\u0097\u0001\u0010\u0094\u0001R\"\u0010\u009d\u0001\u001a\u00030\u0099\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u009a\u0001\u0010I\u001a\u0006\b\u009b\u0001\u0010\u009c\u0001R \u0010 \u0001\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\u000e\n\u0005\b\u009e\u0001\u0010I\u001a\u0005\b\u009f\u0001\u00106R\"\u0010£\u0001\u001a\u00030\u0091\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b¡\u0001\u0010I\u001a\u0006\b¢\u0001\u0010\u0094\u0001R'\u0010¤\u0001\u001a\u00020\u00168\u0006@\u0006X\u0086\u000e¢\u0006\u0016\n\u0006\b¤\u0001\u0010¥\u0001\u001a\u0005\b¦\u0001\u0010;\"\u0005\b§\u0001\u0010\u0019R \u0010ª\u0001\u001a\u00020`8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b¨\u0001\u0010I\u001a\u0005\b©\u0001\u0010cR'\u0010«\u0001\u001a\u00020\u00168\u0006@\u0006X\u0086\u000e¢\u0006\u0016\n\u0006\b«\u0001\u0010¥\u0001\u001a\u0005\b¬\u0001\u0010;\"\u0005\b\u00ad\u0001\u0010\u0019¨\u0006°\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/IndexActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/index/IndexViewModel;", "", "showMineTab", "()V", "Lcom/jbzd/media/movecartoons/bean/event/EventChangeTab;", "target", "changeTab", "(Lcom/jbzd/media/movecartoons/bean/event/EventChangeTab;)V", "checkAudioStatus", "showNotice", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "adBean", "doAdsDialogLogic", "(Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;)V", "Landroid/graphics/drawable/Drawable;", "drawable", "ad", "showActivityAdsDialog", "(Landroid/graphics/drawable/Drawable;Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;)V", "initBottomNav", "", "position", "showTabStyle", "(I)V", "Lcom/youth/banner/Banner;", "bannerView", "bottom_ad", "initBannerView", "(Lcom/youth/banner/Banner;Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;)V", "drawableResId", "getDrawableByRes", "(I)Landroid/graphics/drawable/Drawable;", "colorResId", "Landroid/content/res/ColorStateList;", "getColorByRes", "(I)Landroid/content/res/ColorStateList;", "", "doCheckCanExit", "()Z", "closeAppLock", "Landroid/content/Intent;", "intent", "onNewIntent", "(Landroid/content/Intent;)V", "eventChangeTab", "onEventDownload", "onResume", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/index/IndexViewModel;", "onStart", "onDestroy", "bindEvent", "getLayoutId", "()I", "keyCode", "Landroid/view/KeyEvent;", NotificationCompat.CATEGORY_EVENT, "onKeyDown", "(ILandroid/view/KeyEvent;)Z", "exitApp", "requestCode", "resultCode", "data", "onActivityResult", "(IILandroid/content/Intent;)V", "Lcom/jbzd/media/movecartoons/view/text/MyRadioButton;", "rad_ai$delegate", "Lkotlin/Lazy;", "getRad_ai", "()Lcom/jbzd/media/movecartoons/view/text/MyRadioButton;", "rad_ai", "Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "circle_iv_music_cover$delegate", "getCircle_iv_music_cover", "()Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "circle_iv_music_cover", "Lcom/qunidayede/service/ServerManager;", "serviceManager$delegate", "getServiceManager", "()Lcom/qunidayede/service/ServerManager;", "serviceManager", "banner_index_item", "Lcom/youth/banner/Banner;", "getBanner_index_item", "()Lcom/youth/banner/Banner;", "setBanner_index_item", "(Lcom/youth/banner/Banner;)V", "rad_video$delegate", "getRad_video", "rad_video", "Landroid/view/View;", "v_divider$delegate", "getV_divider", "()Landroid/view/View;", "v_divider", "Landroid/widget/LinearLayout;", "ll_home_ad$delegate", "getLl_home_ad", "()Landroid/widget/LinearLayout;", "ll_home_ad", "rad_bcy$delegate", "getRad_bcy", "rad_bcy", "rad_dark$delegate", "getRad_dark", "rad_dark", "rad_mine$delegate", "getRad_mine", "rad_mine", "Ljava/util/ArrayList;", "Lcom/qunidayede/supportlibrary/core/view/BaseFragment;", "Lkotlin/collections/ArrayList;", "fragments$delegate", "getFragments", "()Ljava/util/ArrayList;", "fragments", "Landroid/animation/ObjectAnimator;", "albumAnimatorBig", "Landroid/animation/ObjectAnimator;", "getAlbumAnimatorBig", "()Landroid/animation/ObjectAnimator;", "setAlbumAnimatorBig", "(Landroid/animation/ObjectAnimator;)V", "", "startTime", "J", "rad_community$delegate", "getRad_community", "rad_community", "Landroid/widget/RadioGroup;", "rg_nav$delegate", "getRg_nav", "()Landroid/widget/RadioGroup;", "rg_nav", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "pageAdapter$delegate", "getPageAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "pageAdapter", "Landroid/widget/ImageView;", "iv_pause_button$delegate", "getIv_pause_button", "()Landroid/widget/ImageView;", "iv_pause_button", "iv_cose_button$delegate", "getIv_cose_button", "iv_cose_button", "Lcom/jbzd/media/movecartoons/view/NoScrollViewPager;", "vp_content$delegate", "getVp_content", "()Lcom/jbzd/media/movecartoons/view/NoScrollViewPager;", "vp_content", "viewModel$delegate", "getViewModel", "viewModel", "close$delegate", "getClose", "close", "adLength", "I", "getAdLength", "setAdLength", "ll_tools_layout$delegate", "getLl_tools_layout", "ll_tools_layout", "currentAdPosition", "getCurrentAdPosition", "setCurrentAdPosition", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class IndexActivity extends MyThemeViewModelActivity<IndexViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static List<? extends AdBean> bannersIndex = null;

    @NotNull
    public static final String key_home_tab = "home_tab";

    @NotNull
    public static final String key_mine_tab = "mine_tab";
    private int adLength;

    @Nullable
    private ObjectAnimator albumAnimatorBig;
    public Banner<?, ?> banner_index_item;
    private int currentAdPosition;
    private long startTime;

    /* renamed from: serviceManager$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy serviceManager = LazyKt__LazyJVMKt.lazy(new Function0<ServerManager>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$serviceManager$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ServerManager invoke() {
            return new ServerManager(IndexActivity.this);
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<BaseFragment>>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$fragments$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<BaseFragment> invoke() {
            return CollectionsKt__CollectionsKt.arrayListOf(HomeBCYFragment.Companion.newInstance(), HomeFragment.INSTANCE.newInstance("normal", BottomTab.Tab1.INSTANCE, ""), new AiAreaFragment(), PostHomeFragment.Companion.newInstance(BottomTab.Tab3.INSTANCE), new MineFragment());
        }
    });

    /* renamed from: pageAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy pageAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$pageAdapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList fragments;
            FragmentManager supportFragmentManager = IndexActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            fragments = IndexActivity.this.getFragments();
            return new ViewPagerAdapter(supportFragmentManager, fragments, 0, 4, null);
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<NoScrollViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final NoScrollViewPager invoke() {
            NoScrollViewPager noScrollViewPager = (NoScrollViewPager) IndexActivity.this.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(noScrollViewPager);
            return noScrollViewPager;
        }
    });

    /* renamed from: ll_tools_layout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_tools_layout = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$ll_tools_layout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final View invoke() {
            View findViewById = IndexActivity.this.findViewById(R.id.ll_tools_layout);
            Intrinsics.checkNotNull(findViewById);
            return findViewById;
        }
    });

    /* renamed from: circle_iv_music_cover$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy circle_iv_music_cover = LazyKt__LazyJVMKt.lazy(new Function0<CircleImageView>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$circle_iv_music_cover$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CircleImageView invoke() {
            CircleImageView circleImageView = (CircleImageView) IndexActivity.this.findViewById(R.id.circle_iv_music_cover);
            Intrinsics.checkNotNull(circleImageView);
            return circleImageView;
        }
    });

    /* renamed from: iv_pause_button$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_pause_button = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$iv_pause_button$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) IndexActivity.this.findViewById(R.id.iv_pause_button);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: iv_cose_button$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_cose_button = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$iv_cose_button$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) IndexActivity.this.findViewById(R.id.iv_cose_button);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(IndexViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$special$$inlined$viewModels$default$1
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

    /* renamed from: close$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy close = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$close$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) IndexActivity.this.findViewById(R.id.close);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: rg_nav$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rg_nav = LazyKt__LazyJVMKt.lazy(new Function0<RadioGroup>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$rg_nav$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RadioGroup invoke() {
            RadioGroup radioGroup = (RadioGroup) IndexActivity.this.findViewById(R.id.rg_nav);
            Intrinsics.checkNotNull(radioGroup);
            return radioGroup;
        }
    });

    /* renamed from: ll_home_ad$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_home_ad = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$ll_home_ad$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) IndexActivity.this.findViewById(R.id.ll_home_ad);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: v_divider$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy v_divider = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$v_divider$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final View invoke() {
            View findViewById = IndexActivity.this.findViewById(R.id.v_divider);
            Intrinsics.checkNotNull(findViewById);
            return findViewById;
        }
    });

    /* renamed from: rad_bcy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_bcy = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$rad_bcy$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) IndexActivity.this.findViewById(R.id.rad_bcy);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    /* renamed from: rad_video$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_video = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$rad_video$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) IndexActivity.this.findViewById(R.id.rad_video);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    /* renamed from: rad_ai$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_ai = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$rad_ai$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) IndexActivity.this.findViewById(R.id.rad_ai);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    /* renamed from: rad_community$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_community = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$rad_community$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) IndexActivity.this.findViewById(R.id.rad_community);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    /* renamed from: rad_mine$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_mine = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$rad_mine$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) IndexActivity.this.findViewById(R.id.rad_mine);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    /* renamed from: rad_dark$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_dark = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$rad_dark$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) IndexActivity.this.findViewById(R.id.rad_dark);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\u0006\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0019\u0010\u001aJ+\u0010\t\u001a\u00020\b2\u0006\u0010\u0003\u001a\u00020\u00022\n\b\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u00042\b\b\u0002\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\t\u0010\nJ\u0015\u0010\u000b\u001a\u00020\b2\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u000b\u0010\fR(\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u000e0\r8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014R\u0016\u0010\u0016\u001a\u00020\u00158\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0016\u0010\u0017R\u0016\u0010\u0018\u001a\u00020\u00158\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0018\u0010\u0017¨\u0006\u001b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/IndexActivity$Companion;", "", "Landroid/content/Context;", "context", "Lcom/jbzd/media/movecartoons/bean/event/EventChangeTab;", "eventChangeTab", "", "showMine", "", "start", "(Landroid/content/Context;Lcom/jbzd/media/movecartoons/bean/event/EventChangeTab;Z)V", "startShowMine", "(Landroid/content/Context;)V", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "bannersIndex", "Ljava/util/List;", "getBannersIndex", "()Ljava/util/List;", "setBannersIndex", "(Ljava/util/List;)V", "", "key_home_tab", "Ljava/lang/String;", "key_mine_tab", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void start$default(Companion companion, Context context, EventChangeTab eventChangeTab, boolean z, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                eventChangeTab = null;
            }
            if ((i2 & 4) != 0) {
                z = false;
            }
            companion.start(context, eventChangeTab, z);
        }

        @NotNull
        public final List<AdBean> getBannersIndex() {
            List list = IndexActivity.bannersIndex;
            if (list != null) {
                return list;
            }
            Intrinsics.throwUninitializedPropertyAccessException("bannersIndex");
            throw null;
        }

        public final void setBannersIndex(@NotNull List<? extends AdBean> list) {
            Intrinsics.checkNotNullParameter(list, "<set-?>");
            IndexActivity.bannersIndex = list;
        }

        public final void start(@NotNull Context context, @Nullable EventChangeTab eventChangeTab, boolean showMine) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) IndexActivity.class);
            intent.putExtra(IndexActivity.key_home_tab, eventChangeTab);
            intent.putExtra(IndexActivity.key_mine_tab, showMine);
            context.startActivity(intent);
        }

        public final void startShowMine(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            start$default(this, context, null, false, 2, null);
        }
    }

    private final void changeTab(EventChangeTab target) {
        getVp_content().setCurrentItem(target.getTabIndex());
        Fragment fragment = getPageAdapter().getFragment(target.getTabIndex());
        if (fragment instanceof HomeFragment) {
            ((HomeFragment) fragment).showTab(target.getTabId());
        }
    }

    private final void checkAudioStatus() {
        NovelChapter novelChapter;
        if (getAudioService().f572c) {
            if (!Intrinsics.areEqual(getAudioService().m298a().isPlaying.getValue(), Boolean.TRUE)) {
                getLl_tools_layout().setVisibility(8);
                return;
            }
            getLl_tools_layout().setVisibility(0);
            C2852c m2467d2 = C2354n.m2467d2(this);
            NovelChapterInfoBean value = getAudioService().m298a().m4202d().getValue();
            String str = null;
            if (value != null && (novelChapter = value.chapter) != null) {
                str = novelChapter.img;
            }
            m2467d2.m3298p(str).m3292f0().m757R(getCircle_iv_music_cover());
            ObjectAnimator objectAnimator = this.albumAnimatorBig;
            if (objectAnimator == null) {
                ObjectAnimator ofFloat = ObjectAnimator.ofFloat(getCircle_iv_music_cover(), Key.ROTATION, 0.0f, 360.0f);
                this.albumAnimatorBig = ofFloat;
                if (ofFloat != null) {
                    ofFloat.setDuration(PlayModeFragment.DURATION_SLOW_ROTATION);
                }
                ObjectAnimator objectAnimator2 = this.albumAnimatorBig;
                if (objectAnimator2 != null) {
                    objectAnimator2.setRepeatCount(-1);
                }
                ObjectAnimator objectAnimator3 = this.albumAnimatorBig;
                if (objectAnimator3 != null) {
                    objectAnimator3.setInterpolator(new LinearInterpolator());
                }
                ObjectAnimator objectAnimator4 = this.albumAnimatorBig;
                if (objectAnimator4 != null) {
                    objectAnimator4.start();
                }
            } else {
                objectAnimator.resume();
            }
            C2354n.m2374A(getLl_tools_layout(), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$checkAudioStatus$1
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(View view) {
                    invoke2(view);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull View it) {
                    String str2;
                    Intrinsics.checkNotNullParameter(it, "it");
                    NovelChapterInfoBean value2 = IndexActivity.this.getAudioService().m298a().m4202d().getValue();
                    NovelChapter novelChapter2 = value2 == null ? null : value2.chapter;
                    if (novelChapter2 == null || (str2 = novelChapter2.f10026id) == null) {
                        return;
                    }
                    IndexActivity indexActivity = IndexActivity.this;
                    NovelDetailInfoBean value3 = indexActivity.getAudioService().m298a().m4203e().getValue();
                    if (value3 == null) {
                        return;
                    }
                    AudioPlayerActivity.INSTANCE.start(indexActivity, str2, value3);
                }
            }, 1);
            C2354n.m2374A(getIv_pause_button(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$checkAudioStatus$2
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
                    C2852c m2467d22 = C2354n.m2467d2(IndexActivity.this);
                    Boolean value2 = IndexActivity.this.getAudioService().m298a().isPlaying.getValue();
                    Boolean bool = Boolean.TRUE;
                    m2467d22.m3297o(Integer.valueOf(Intrinsics.areEqual(value2, bool) ? R.drawable.float_pause_button : R.drawable.float_play_button)).m3292f0().m757R(IndexActivity.this.getIv_pause_button());
                    if (Intrinsics.areEqual(IndexActivity.this.getAudioService().m298a().isPlaying.getValue(), bool)) {
                        AudioPlayerService m298a = IndexActivity.this.getAudioService().m298a();
                        final IndexActivity indexActivity = IndexActivity.this;
                        m298a.m4207i(indexActivity, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$checkAudioStatus$2.1
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
                                ObjectAnimator albumAnimatorBig;
                                ObjectAnimator albumAnimatorBig2 = IndexActivity.this.getAlbumAnimatorBig();
                                if (!Intrinsics.areEqual(albumAnimatorBig2 == null ? null : Boolean.valueOf(albumAnimatorBig2.isRunning()), Boolean.TRUE) || (albumAnimatorBig = IndexActivity.this.getAlbumAnimatorBig()) == null) {
                                    return;
                                }
                                albumAnimatorBig.pause();
                            }
                        });
                    } else {
                        AudioPlayerService m298a2 = IndexActivity.this.getAudioService().m298a();
                        final IndexActivity indexActivity2 = IndexActivity.this;
                        m298a2.m4216r(indexActivity2, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$checkAudioStatus$2.2
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
                                ObjectAnimator albumAnimatorBig;
                                if (IndexActivity.this.getAlbumAnimatorBig() == null || (albumAnimatorBig = IndexActivity.this.getAlbumAnimatorBig()) == null) {
                                    return;
                                }
                                albumAnimatorBig.start();
                            }
                        });
                    }
                }
            }, 1);
            C2354n.m2374A(getIv_cose_button(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$checkAudioStatus$3
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
                    if (Intrinsics.areEqual(IndexActivity.this.getAudioService().m298a().isPlaying.getValue(), Boolean.TRUE)) {
                        AudioPlayerService m298a = IndexActivity.this.getAudioService().m298a();
                        final IndexActivity indexActivity = IndexActivity.this;
                        m298a.m4207i(indexActivity, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$checkAudioStatus$3.1
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
                                IndexActivity.this.getAudioService().m298a().stopSelf();
                            }
                        });
                    }
                    IndexActivity.this.getLl_tools_layout().setVisibility(8);
                }
            }, 1);
        }
    }

    private final void closeAppLock() {
        Intrinsics.checkNotNullParameter("", "answer");
        Intrinsics.checkNotNullParameter("lock_pass_word", "key");
        Intrinsics.checkNotNullParameter("", "value");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
        editor.putString("lock_pass_word", "");
        editor.commit();
    }

    private final void doAdsDialogLogic(AdBean adBean) {
        if (!TextUtils.isEmpty(adBean.f10014id)) {
            String str = adBean.content;
            if (str == null) {
                str = "";
            }
            IndexActivity$doAdsDialogLogic$1 indexActivity$doAdsDialogLogic$1 = new IndexActivity$doAdsDialogLogic$1(this, adBean);
            try {
                C1779f c1779f = new C1779f();
                c1779f.mo1086i(AbstractC1643k.f2222a);
                C1558h<Drawable> mo758S = ComponentCallbacks2C1553c.m738h(this).mo778k(c1779f).mo770c().mo763X(str).mo758S(new C0876x(indexActivity$doAdsDialogLogic$1));
                Objects.requireNonNull(mo758S);
                C1777d c1777d = new C1777d(Integer.MIN_VALUE, Integer.MIN_VALUE);
                mo758S.m756Q(c1777d, c1777d, mo758S, C1802d.f2756b);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    private final boolean doCheckCanExit() {
        Fragment fragment = getPageAdapter().getFragment(getVp_content().getCurrentItem());
        if (fragment instanceof FoundFragment) {
            return ((FoundFragment) fragment).canGoBackAct();
        }
        return true;
    }

    private final ColorStateList getColorByRes(int colorResId) {
        return AppCompatResources.getColorStateList(this, colorResId);
    }

    private final Drawable getDrawableByRes(int drawableResId) {
        return AppCompatResources.getDrawable(this, drawableResId);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<BaseFragment> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    private final ViewPagerAdapter getPageAdapter() {
        return (ViewPagerAdapter) this.pageAdapter.getValue();
    }

    private final ServerManager getServiceManager() {
        return (ServerManager) this.serviceManager.getValue();
    }

    private final IndexViewModel getViewModel() {
        return (IndexViewModel) this.viewModel.getValue();
    }

    private final void initBannerView(Banner<?, ?> bannerView, final AdBean bottom_ad) {
        if (bottom_ad == null) {
            bannerView.setVisibility(8);
            return;
        }
        bannerView.setIntercept(CollectionsKt__CollectionsKt.arrayListOf(bottom_ad).size() != 1);
        Banner addBannerLifecycleObserver = bannerView.addBannerLifecycleObserver(this);
        ArrayList arrayListOf = CollectionsKt__CollectionsKt.arrayListOf(bottom_ad);
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayListOf, 10));
        Iterator it = arrayListOf.iterator();
        while (it.hasNext()) {
            arrayList.add(((AdBean) it.next()).content);
        }
        addBannerLifecycleObserver.setAdapter(new BannerAdapterImp(this, arrayList, 0.0f, 99.0d, null, 16));
        bannerView.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.g.h
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                IndexActivity.m5805initBannerView$lambda11$lambda10(IndexActivity.this, bottom_ad, obj, i2);
            }
        });
        bannerView.setIndicator(new RectangleIndicator(this));
        bannerView.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBannerView$lambda-11$lambda-10, reason: not valid java name */
    public static final void m5805initBannerView$lambda11$lambda10(IndexActivity this$0, AdBean bottom_ad, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(bottom_ad, "$bottom_ad");
        C0840d.a aVar = C0840d.f235a;
        Object obj2 = CollectionsKt__CollectionsKt.arrayListOf(bottom_ad).get(i2);
        Intrinsics.checkNotNullExpressionValue(obj2, "arrayListOf(bottom_ad)[position]");
        aVar.m176b(this$0, (AdBean) obj2);
    }

    private final void initBottomNav() {
        C2354n.m2374A(getClose(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$initBottomNav$1
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
                IndexActivity.this.getClose().setVisibility(8);
                IndexActivity.this.getBanner_index_item().setVisibility(8);
            }
        }, 1);
        getVp_content().setOffscreenPageLimit(getFragments().size());
        NoScrollViewPager vp_content = getVp_content();
        vp_content.setAdapter(getPageAdapter());
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.IndexActivity$initBottomNav$2$1
            private int lastPage = -1;

            public final int getLastPage() {
                return this.lastPage;
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                String act = position != 0 ? position != 1 ? position != 2 ? position != 3 ? position != 4 ? position != 5 ? "bottom_tab7" : "bottom_tab6" : "bottom_tab5" : "bottom_tab4" : "bottom_tab3" : "bottom_tab2" : "bottom_tab1";
                Intrinsics.checkNotNullParameter(act, "act");
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                linkedHashMap.put("act", act);
                C0917a.m221e(C0917a.f372a, "system/doLogs", Object.class, linkedHashMap, C0846g.f248c, null, false, false, null, false, 432);
                IndexActivity.this.getRg_nav().check(position != 0 ? position != 1 ? position != 2 ? position != 3 ? R.id.rad_mine : R.id.rad_community : R.id.rad_ai : R.id.rad_video : R.id.rad_bcy);
                IndexActivity.this.showTabStyle(position);
                if (this.lastPage != position) {
                    if (position == 0) {
                        IndexActivity.this.getBanner_index_item().setVisibility(0);
                        IndexActivity.this.getClose().setVisibility(0);
                    } else {
                        IndexActivity.this.getBanner_index_item().setVisibility(8);
                        IndexActivity.this.getClose().setVisibility(8);
                    }
                }
                this.lastPage = position;
            }

            public final void setLastPage(int i2) {
                this.lastPage = i2;
            }
        });
        getRg_nav().setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: b.a.a.a.t.g.e
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup, int i2) {
                IndexActivity.m5806initBottomNav$lambda7(IndexActivity.this, radioGroup, i2);
            }
        });
        getRg_nav().check(R.id.rad_bcy);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBottomNav$lambda-7, reason: not valid java name */
    public static final void m5806initBottomNav$lambda7(IndexActivity this$0, RadioGroup radioGroup, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        NoScrollViewPager vp_content = this$0.getVp_content();
        switch (i2) {
            case R.id.rad_ai /* 2131362997 */:
                i3 = 2;
                break;
            case R.id.rad_bcy /* 2131362998 */:
                i3 = 0;
                break;
            case R.id.rad_community /* 2131363002 */:
                i3 = 3;
                break;
            case R.id.rad_video /* 2131363005 */:
                i3 = 1;
                break;
            default:
                i3 = 5;
                break;
        }
        vp_content.setCurrentItem(i3, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showActivityAdsDialog(Drawable drawable, final AdBean ad) {
        final ActivityReminderDialog activityReminderDialog = new ActivityReminderDialog(this);
        activityReminderDialog.show();
        activityReminderDialog.setCanceledOnTouchOutside(true);
        activityReminderDialog.setImage(drawable);
        activityReminderDialog.setClicklistener(new View.OnClickListener() { // from class: b.a.a.a.t.g.b
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                IndexActivity.m5807showActivityAdsDialog$lambda2(AdBean.this, this, activityReminderDialog, view);
            }
        });
        activityReminderDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: b.a.a.a.t.g.d
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                IndexActivity.m5808showActivityAdsDialog$lambda5(IndexActivity.this, dialogInterface);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showActivityAdsDialog$lambda-2, reason: not valid java name */
    public static final void m5807showActivityAdsDialog$lambda2(AdBean adBean, IndexActivity this$0, ActivityReminderDialog dialog, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(dialog, "$dialog");
        if (adBean != null) {
            C0840d.a aVar = C0840d.f235a;
            String str = adBean.link;
            Intrinsics.checkNotNullExpressionValue(str, "ad.link");
            aVar.m175a(this$0, str);
        }
        dialog.dismiss();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showActivityAdsDialog$lambda-5, reason: not valid java name */
    public static final void m5808showActivityAdsDialog$lambda5(final IndexActivity this$0, DialogInterface dialogInterface) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter("close_appstore", "act");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("act", "close_appstore");
        C0917a.m221e(C0917a.f372a, "system/doLogs", Object.class, linkedHashMap, C0846g.f248c, null, false, false, null, false, 432);
        if (this$0.getCurrentAdPosition() == this$0.getAdLength() - 1) {
            this$0.showNotice();
        } else {
            this$0.setCurrentAdPosition(this$0.getCurrentAdPosition() + 1);
            this$0.runOnUiThread(new Runnable() { // from class: b.a.a.a.t.g.c
                @Override // java.lang.Runnable
                public final void run() {
                    IndexActivity.m5809showActivityAdsDialog$lambda5$lambda4(IndexActivity.this);
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showActivityAdsDialog$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5809showActivityAdsDialog$lambda5$lambda4(final IndexActivity this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        new Handler().postDelayed(new Runnable() { // from class: b.a.a.a.t.g.a
            @Override // java.lang.Runnable
            public final void run() {
                IndexActivity.m5810showActivityAdsDialog$lambda5$lambda4$lambda3(IndexActivity.this);
            }
        }, 150L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showActivityAdsDialog$lambda-5$lambda-4$lambda-3, reason: not valid java name */
    public static final void m5810showActivityAdsDialog$lambda5$lambda4$lambda3(IndexActivity this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        MyApp myApp = MyApp.f9891f;
        AdBean adBean = MyApp.m4185f().layer_ad.get(this$0.getCurrentAdPosition());
        Intrinsics.checkNotNullExpressionValue(adBean, "MyApp.systemBean.layer_ad.get(\n                                currentAdPosition\n                            )");
        this$0.doAdsDialogLogic(adBean);
    }

    private final void showMineTab() {
        getVp_content().setCurrentItem(getFragments().size() - 1);
    }

    private final void showNotice() {
        MyApp myApp = MyApp.f9891f;
        if (MyApp.m4185f().notice != null) {
            String str = MyApp.m4185f().notice.content;
            Intrinsics.checkNotNullExpressionValue(str, "MyApp.systemBean.notice.content");
            new NoticeDialog(str).show(getSupportFragmentManager(), "noticeDialog");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showTabStyle(int position) {
        if (position == 4 || position == 5) {
            getLl_home_ad().setVisibility(8);
        } else {
            getLl_home_ad().setVisibility(0);
        }
        if (getCurThemeFlag()) {
            getV_divider().setVisibility(8);
            getRad_bcy().setTextColor(getColorByRes(R.color.nav_text_color_selector_day));
            getRad_video().setTextColor(getColorByRes(R.color.nav_text_color_selector_day));
            getRad_dark().setTextColor(getColorByRes(R.color.nav_text_color_selector_day));
            getRad_ai().setTextColor(getColorByRes(R.color.nav_text_color_selector_day));
            getRad_community().setTextColor(getColorByRes(R.color.nav_text_color_selector_day));
            getRad_mine().setTextColor(getColorByRes(R.color.nav_text_color_selector_day));
            getRad_bcy().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_tab1_selector_night), (Drawable) null, (Drawable) null);
            getRad_video().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_tab3_selector_night), (Drawable) null, (Drawable) null);
            getRad_dark().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_video_selector), (Drawable) null, (Drawable) null);
            getRad_ai().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_ai_selector), (Drawable) null, (Drawable) null);
            getRad_community().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_tab5_selector), (Drawable) null, (Drawable) null);
            getRad_mine().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_tab4_mine), (Drawable) null, (Drawable) null);
            return;
        }
        getV_divider().setVisibility(8);
        getRad_bcy().setTextColor(getColorByRes(R.color.nav_text_color_selector_night));
        getRad_video();
        getRad_video().setTextColor(getColorByRes(R.color.nav_text_color_selector_night));
        getRad_video().setTextColor(getColorByRes(R.color.nav_text_color_selector_night));
        getRad_ai().setTextColor(getColorByRes(R.color.nav_text_color_selector_night));
        getRad_community().setTextColor(getColorByRes(R.color.nav_text_color_selector_night));
        getRad_mine().setTextColor(getColorByRes(R.color.nav_text_color_selector_night));
        getRad_bcy().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_tab1_selector_night), (Drawable) null, (Drawable) null);
        getRad_video().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_tab3_selector_night), (Drawable) null, (Drawable) null);
        getRad_dark().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_video_selector), (Drawable) null, (Drawable) null);
        getRad_ai().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_ai_selector), (Drawable) null, (Drawable) null);
        getRad_community().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_tab5_selector), (Drawable) null, (Drawable) null);
        getRad_mine().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, getDrawableByRes(R.drawable.nav_tab4_mine), (Drawable) null, (Drawable) null);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        ServerManager serviceManager = getServiceManager();
        serviceManager.f10279a.startService(serviceManager.f10280b);
    }

    public final void exitApp() {
        ActivityCompat.finishAffinity(this);
        try {
            try {
                System.exit(0);
                throw new RuntimeException("System.exit returned normally, while it was supposed to halt JVM.");
            } catch (Exception unused) {
                Process.killProcess(Process.myPid());
            }
        } catch (Exception unused2) {
        }
    }

    public final int getAdLength() {
        return this.adLength;
    }

    @Nullable
    public final ObjectAnimator getAlbumAnimatorBig() {
        return this.albumAnimatorBig;
    }

    @NotNull
    public final Banner<?, ?> getBanner_index_item() {
        Banner<?, ?> banner = this.banner_index_item;
        if (banner != null) {
            return banner;
        }
        Intrinsics.throwUninitializedPropertyAccessException("banner_index_item");
        throw null;
    }

    @NotNull
    public final CircleImageView getCircle_iv_music_cover() {
        return (CircleImageView) this.circle_iv_music_cover.getValue();
    }

    @NotNull
    public final ImageView getClose() {
        return (ImageView) this.close.getValue();
    }

    public final int getCurrentAdPosition() {
        return this.currentAdPosition;
    }

    @NotNull
    public final ImageView getIv_cose_button() {
        return (ImageView) this.iv_cose_button.getValue();
    }

    @NotNull
    public final ImageView getIv_pause_button() {
        return (ImageView) this.iv_pause_button.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.activity_index;
    }

    @NotNull
    public final LinearLayout getLl_home_ad() {
        return (LinearLayout) this.ll_home_ad.getValue();
    }

    @NotNull
    public final View getLl_tools_layout() {
        return (View) this.ll_tools_layout.getValue();
    }

    @NotNull
    public final MyRadioButton getRad_ai() {
        return (MyRadioButton) this.rad_ai.getValue();
    }

    @NotNull
    public final MyRadioButton getRad_bcy() {
        return (MyRadioButton) this.rad_bcy.getValue();
    }

    @NotNull
    public final MyRadioButton getRad_community() {
        return (MyRadioButton) this.rad_community.getValue();
    }

    @NotNull
    public final MyRadioButton getRad_dark() {
        return (MyRadioButton) this.rad_dark.getValue();
    }

    @NotNull
    public final MyRadioButton getRad_mine() {
        return (MyRadioButton) this.rad_mine.getValue();
    }

    @NotNull
    public final MyRadioButton getRad_video() {
        return (MyRadioButton) this.rad_video.getValue();
    }

    @NotNull
    public final RadioGroup getRg_nav() {
        return (RadioGroup) this.rg_nav.getValue();
    }

    @NotNull
    public final View getV_divider() {
        return (View) this.v_divider.getValue();
    }

    @NotNull
    public final NoScrollViewPager getVp_content() {
        return (NoScrollViewPager) this.vp_content.getValue();
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 10020 && data != null && data.getBooleanExtra("KEY_VERIFICATION_OK", false)) {
            closeAppLock();
        }
    }

    /* JADX WARN: Type inference failed for: r14v12, types: [T, java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r14v13, types: [T, java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r14v19, types: [T, java.util.List] */
    /* JADX WARN: Type inference failed for: r2v10, types: [T, java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v12, types: [T, java.util.List<com.jbzd.media.movecartoons.bean.response.AppItemNew>] */
    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ServerManager serviceManager = getServiceManager();
        Objects.requireNonNull(serviceManager);
        serviceManager.f10279a.registerReceiver(serviceManager, new IntentFilter("com.xjbg.andserver.receiver"));
        C0959d0 audioService = getAudioService();
        Objects.requireNonNull(audioService);
        Intrinsics.checkNotNullParameter(this, "context");
        bindService(new Intent(this, (Class<?>) AudioPlayerService.class), audioService.f573d, 1);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        MineViewModel.INSTANCE.getUserInfo();
        initBottomNav();
        View findViewById = findViewById(R.id.banner_index_item);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.banner_index_item)");
        setBanner_index_item((Banner) findViewById);
        MyApp myApp = MyApp.f9891f;
        if (MyApp.m4185f().bottom_ad != null) {
            Banner<?, ?> banner_index_item = getBanner_index_item();
            AdBean adBean = MyApp.m4185f().bottom_ad;
            Intrinsics.checkNotNullExpressionValue(adBean, "MyApp.systemBean.bottom_ad");
            initBannerView(banner_index_item, adBean);
        }
        Ref.ObjectRef objectRef = new Ref.ObjectRef();
        Ref.ObjectRef objectRef2 = new Ref.ObjectRef();
        Ref.ObjectRef objectRef3 = new Ref.ObjectRef();
        objectRef3.element = new ArrayList();
        Ref.ObjectRef objectRef4 = new Ref.ObjectRef();
        objectRef4.element = new ArrayList();
        List<TypeAdBean> list = MyApp.m4185f().layer;
        if (list != null) {
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(list, 10));
            for (TypeAdBean typeAdBean : list) {
                if (Intrinsics.areEqual(typeAdBean.type, "apps")) {
                    objectRef2.element = typeAdBean.data.items;
                }
                if (Intrinsics.areEqual(typeAdBean.type, "notice")) {
                    objectRef.element = typeAdBean.data.content;
                }
                if (Intrinsics.areEqual(typeAdBean.type, "ad")) {
                    List list2 = (List) objectRef3.element;
                    AdBean adBean2 = typeAdBean.data;
                    Intrinsics.checkNotNullExpressionValue(adBean2, "it.data");
                    list2.add(adBean2);
                }
                arrayList.add(Unit.INSTANCE);
            }
        }
        objectRef4.element = TypeIntrinsics.asMutableList(CollectionsKt___CollectionsKt.chunked((Iterable) objectRef3.element, 3));
        C2354n.m2435U0(LifecycleOwnerKt.getLifecycleScope(this), null, 0, new IndexActivity$onCreate$3(objectRef2, objectRef4, objectRef3, objectRef, this, null), 3, null);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        ServerManager serviceManager = getServiceManager();
        serviceManager.f10279a.unregisterReceiver(serviceManager);
        C4909c.m5569b().m5580m(this);
        if (getAudioService().m298a().isServiceBound) {
            getAudioService().m299b(false);
            unbindService(getAudioService().f573d);
        }
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onEventDownload(@NotNull EventChangeTab eventChangeTab) {
        Intrinsics.checkNotNullParameter(eventChangeTab, "eventChangeTab");
        changeTab(eventChangeTab);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, android.app.Activity, android.view.KeyEvent.Callback
    public boolean onKeyDown(int keyCode, @Nullable KeyEvent event) {
        if (keyCode != 4) {
            return super.onKeyDown(keyCode, event);
        }
        if (!doCheckCanExit()) {
            return true;
        }
        if (System.currentTimeMillis() - this.startTime <= 2000) {
            exitApp();
            return true;
        }
        C4325a.m4901d(this, "再按一次退出程序").show();
        this.startTime = System.currentTimeMillis();
        return true;
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onNewIntent(@Nullable Intent intent) {
        super.onNewIntent(intent);
        if ((intent == null ? null : intent.getSerializableExtra(key_home_tab)) != null) {
            Serializable serializableExtra = intent != null ? intent.getSerializableExtra(key_home_tab) : null;
            Objects.requireNonNull(serializableExtra, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.event.EventChangeTab");
            EventChangeTab eventChangeTab = (EventChangeTab) serializableExtra;
            if (intent != null ? intent.getBooleanExtra(key_mine_tab, false) : false) {
                showMineTab();
            } else {
                changeTab(eventChangeTab);
            }
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        checkAudioStatus();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onStart() {
        super.onStart();
        if (C4909c.m5569b().m5573f(this)) {
            return;
        }
        C4909c.m5569b().m5578k(this);
    }

    public final void setAdLength(int i2) {
        this.adLength = i2;
    }

    public final void setAlbumAnimatorBig(@Nullable ObjectAnimator objectAnimator) {
        this.albumAnimatorBig = objectAnimator;
    }

    public final void setBanner_index_item(@NotNull Banner<?, ?> banner) {
        Intrinsics.checkNotNullParameter(banner, "<set-?>");
        this.banner_index_item = banner;
    }

    public final void setCurrentAdPosition(int i2) {
        this.currentAdPosition = i2;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public IndexViewModel viewModelInstance() {
        return getViewModel();
    }

    public final void onCreate() {
        super.onStart();
    }
}

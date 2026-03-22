package com.angcyo.tablayout;

import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.animation.LinearInterpolator;
import android.widget.FrameLayout;
import android.widget.OverScroller;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.core.app.NotificationCompat;
import androidx.core.view.GestureDetectorCompat;
import androidx.core.view.ViewCompat;
import com.angcyo.tablayout.C1514k;
import com.angcyo.tablayout.C1520q;
import com.angcyo.tablayout.C1521r;
import com.angcyo.tablayout.C1526w;
import com.angcyo.tablayout.DslGradientDrawable;
import com.angcyo.tablayout.DslSelector;
import com.angcyo.tablayout.DslTabBadge;
import com.angcyo.tablayout.DslTabBorder;
import com.angcyo.tablayout.DslTabDivider;
import com.angcyo.tablayout.DslTabHighlight;
import com.angcyo.tablayout.DslTabIndicator;
import com.angcyo.tablayout.DslTabLayout;
import com.angcyo.tablayout.DslTabLayoutConfig;
import com.angcyo.tablayout.TabBadgeConfig;
import com.angcyo.tablayout.TabGradientCallback;
import com.angcyo.tablayout.ViewPagerDelegate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.Ref;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000\u0088\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\b#\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0010%\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\t\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0002\n\u0002\b\u0006\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u001e\n\u0002\u0010\u000e\n\u0002\b\u0005\b\u0016\u0018\u00002\u00020\u0001:\u0002¥\u0002B\u0019\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\n\b\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u0005¢\u0006\u0002\u0010\u0006J\u001a\u0010Ã\u0001\u001a\u00030Ä\u00012\u0007\u0010Å\u0001\u001a\u00020\b2\u0007\u0010Æ\u0001\u001a\u00020\bJ\u0007\u0010Ç\u0001\u001a\u00020\bJ\u0007\u0010È\u0001\u001a\u00020\bJ\b\u0010É\u0001\u001a\u00030Ä\u0001J\u0012\u0010Ê\u0001\u001a\u00030Ä\u00012\b\u0010\u008a\u0001\u001a\u00030Ë\u0001J\u0019\u0010Ì\u0001\u001a\u00030Ä\u00012\u0006\u0010~\u001a\u00020\b2\u0007\u0010Í\u0001\u001a\u00020BJ\n\u0010Î\u0001\u001a\u00030Ä\u0001H\u0016J(\u0010Ï\u0001\u001a\u00030Ä\u00012\u001e\b\u0002\u0010Ð\u0001\u001a\u0017\u0012\u0005\u0012\u00030½\u0001\u0012\u0005\u0012\u00030Ä\u00010Ñ\u0001¢\u0006\u0003\bÒ\u0001J\u0014\u0010Ó\u0001\u001a\u00030Ä\u00012\b\u0010Ô\u0001\u001a\u00030Õ\u0001H\u0016J%\u0010Ö\u0001\u001a\u00020B2\b\u0010Ô\u0001\u001a\u00030Õ\u00012\u0006\u0010{\u001a\u00020>2\b\u0010×\u0001\u001a\u00030¸\u0001H\u0014J\n\u0010Ø\u0001\u001a\u00030Ù\u0001H\u0014J\u0015\u0010Ú\u0001\u001a\u00030Ù\u00012\t\u0010Û\u0001\u001a\u0004\u0018\u00010\u0005H\u0016J\u0016\u0010Ú\u0001\u001a\u00030Ù\u00012\n\u0010Ü\u0001\u001a\u0005\u0018\u00010Ù\u0001H\u0014J\u000f\u0010Ý\u0001\u001a\u00020\u007f2\u0006\u0010~\u001a\u00020\bJ\u0007\u0010Þ\u0001\u001a\u00020BJ5\u0010ß\u0001\u001a\u00030Ä\u00012\u0007\u0010à\u0001\u001a\u00020B2\u0007\u0010á\u0001\u001a\u00020\b2\u0007\u0010â\u0001\u001a\u00020\b2\u0007\u0010ã\u0001\u001a\u00020\b2\u0007\u0010ä\u0001\u001a\u00020\bJ5\u0010å\u0001\u001a\u00030Ä\u00012\u0007\u0010à\u0001\u001a\u00020B2\u0007\u0010á\u0001\u001a\u00020\b2\u0007\u0010â\u0001\u001a\u00020\b2\u0007\u0010ã\u0001\u001a\u00020\b2\u0007\u0010ä\u0001\u001a\u00020\bJ\u001a\u0010æ\u0001\u001a\u00030Ä\u00012\u0007\u0010ç\u0001\u001a\u00020\b2\u0007\u0010è\u0001\u001a\u00020\bJ\u001a\u0010é\u0001\u001a\u00030Ä\u00012\u0007\u0010ç\u0001\u001a\u00020\b2\u0007\u0010è\u0001\u001a\u00020\bJ\u0091\u0001\u0010ê\u0001\u001a\u00030Ä\u00012\u001e\b\u0002\u0010Ð\u0001\u001a\u0017\u0012\u0005\u0012\u00030½\u0001\u0012\u0005\u0012\u00030Ä\u00010Ñ\u0001¢\u0006\u0003\bÒ\u00012g\u0010ë\u0001\u001ab\u0012\u0014\u0012\u00120\b¢\u0006\r\by\u0012\t\bz\u0012\u0005\b\b(Å\u0001\u0012\u0014\u0012\u00120\b¢\u0006\r\by\u0012\t\bz\u0012\u0005\b\b(Æ\u0001\u0012\u0014\u0012\u00120B¢\u0006\r\by\u0012\t\bz\u0012\u0005\b\b(í\u0001\u0012\u0014\u0012\u00120B¢\u0006\r\by\u0012\t\bz\u0012\u0005\b\b(î\u0001\u0012\u0005\u0012\u00030Ä\u00010ì\u0001J\n\u0010ï\u0001\u001a\u00030Ä\u0001H\u0014J\n\u0010ð\u0001\u001a\u00030Ä\u0001H\u0014J\u0014\u0010ñ\u0001\u001a\u00030Ä\u00012\b\u0010Ô\u0001\u001a\u00030Õ\u0001H\u0014J\n\u0010ò\u0001\u001a\u00030Ä\u0001H\u0014J\u0014\u0010ó\u0001\u001a\u00030Ä\u00012\b\u0010ô\u0001\u001a\u00030Ë\u0001H\u0016J\u0013\u0010õ\u0001\u001a\u00020B2\b\u0010ö\u0001\u001a\u00030÷\u0001H\u0016J7\u0010ø\u0001\u001a\u00030Ä\u00012\u0007\u0010à\u0001\u001a\u00020B2\u0007\u0010á\u0001\u001a\u00020\b2\u0007\u0010â\u0001\u001a\u00020\b2\u0007\u0010ã\u0001\u001a\u00020\b2\u0007\u0010ä\u0001\u001a\u00020\bH\u0014J\u001c\u0010ù\u0001\u001a\u00030Ä\u00012\u0007\u0010ç\u0001\u001a\u00020\b2\u0007\u0010è\u0001\u001a\u00020\bH\u0014J\u0011\u0010ú\u0001\u001a\u00030Ä\u00012\u0007\u0010û\u0001\u001a\u00020\bJ$\u0010ü\u0001\u001a\u00030Ä\u00012\u0007\u0010ý\u0001\u001a\u00020\b2\b\u0010þ\u0001\u001a\u00030Ë\u00012\u0007\u0010ÿ\u0001\u001a\u00020\bJ\u0011\u0010\u0080\u0002\u001a\u00030Ä\u00012\u0007\u0010ý\u0001\u001a\u00020\bJ\u0016\u0010\u0081\u0002\u001a\u00030Ä\u00012\n\u0010û\u0001\u001a\u0005\u0018\u00010\u0082\u0002H\u0014J\u0013\u0010\u0083\u0002\u001a\u00030Ä\u00012\u0007\u0010\u0084\u0002\u001a\u00020\bH\u0016J\f\u0010\u0085\u0002\u001a\u0005\u0018\u00010\u0082\u0002H\u0014J\u0013\u0010\u0086\u0002\u001a\u00020B2\b\u0010\u0087\u0002\u001a\u00030Ë\u0001H\u0016J.\u0010\u0088\u0002\u001a\u00030Ä\u00012\u0007\u0010\u0089\u0002\u001a\u00020\b2\u0007\u0010\u008a\u0002\u001a\u00020\b2\u0007\u0010\u008b\u0002\u001a\u00020\b2\u0007\u0010\u008c\u0002\u001a\u00020\bH\u0014J\u0013\u0010\u008d\u0002\u001a\u00020B2\b\u0010\u008e\u0002\u001a\u00030÷\u0001H\u0016J\u0014\u0010\u008f\u0002\u001a\u00030Ä\u00012\b\u0010{\u001a\u0004\u0018\u00010>H\u0016J\u0014\u0010\u0090\u0002\u001a\u00030Ä\u00012\b\u0010{\u001a\u0004\u0018\u00010>H\u0016J\b\u0010\u0091\u0002\u001a\u00030Ä\u0001J\u001c\u0010\u0092\u0002\u001a\u00030Ä\u00012\u0007\u0010\u0093\u0002\u001a\u00020\b2\u0007\u0010\u0094\u0002\u001a\u00020\bH\u0016J&\u0010\u0095\u0002\u001a\u00030Ä\u00012\u0006\u0010~\u001a\u00020\b2\t\b\u0002\u0010\u0096\u0002\u001a\u00020B2\t\b\u0002\u0010î\u0001\u001a\u00020BJ4\u0010Á\u0001\u001a\u00030Ä\u00012\n\b\u0002\u0010Ð\u0001\u001a\u00030½\u00012\u001e\b\u0002\u0010\u0097\u0002\u001a\u0017\u0012\u0005\u0012\u00030½\u0001\u0012\u0005\u0012\u00030Ä\u00010Ñ\u0001¢\u0006\u0003\bÒ\u0001J\u0011\u0010\u0098\u0002\u001a\u00030Ä\u00012\u0007\u0010\u0099\u0002\u001a\u000201J#\u0010\u009a\u0002\u001a\u00030Ä\u00012\u0007\u0010ô\u0001\u001a\u00020\b2\u0007\u0010\u009b\u0002\u001a\u00020\b2\u0007\u0010\u009c\u0002\u001a\u00020\bJ\u0011\u0010\u009d\u0002\u001a\u00030Ä\u00012\u0007\u0010\u009e\u0002\u001a\u00020\bJ-\u0010\u009f\u0002\u001a\u00030Ä\u00012\u0006\u0010~\u001a\u00020\b2\u001b\u0010Ð\u0001\u001a\u0016\u0012\u0004\u0012\u00020\u007f\u0012\u0005\u0012\u00030Ä\u00010Ñ\u0001¢\u0006\u0003\bÒ\u0001J\u001c\u0010\u009f\u0002\u001a\u00030Ä\u00012\u0006\u0010~\u001a\u00020\b2\n\u0010 \u0002\u001a\u0005\u0018\u00010¡\u0002J\n\u0010¢\u0002\u001a\u00030Ä\u0001H\u0016J\u0013\u0010£\u0002\u001a\u00020B2\b\u0010¤\u0002\u001a\u00030\u009a\u0001H\u0014R\u001a\u0010\u0007\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\fR\u001b\u0010\r\u001a\u00020\u000e8FX\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u000f\u0010\u0010R\u001a\u0010\u0013\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0014\u0010\n\"\u0004\b\u0015\u0010\fR\u001a\u0010\u0016\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0017\u0010\n\"\u0004\b\u0018\u0010\fR\u001a\u0010\u0019\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001a\u0010\n\"\u0004\b\u001b\u0010\fR\u001a\u0010\u001c\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001d\u0010\n\"\u0004\b\u001e\u0010\fR\u001b\u0010\u001f\u001a\u00020 8FX\u0086\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u0012\u001a\u0004\b!\u0010\"R\u001b\u0010$\u001a\u00020%8FX\u0086\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u0012\u001a\u0004\b&\u0010'R\u0011\u0010)\u001a\u00020*¢\u0006\b\n\u0000\u001a\u0004\b+\u0010,R\u001a\u0010-\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b.\u0010\n\"\u0004\b/\u0010\fR\u001c\u00100\u001a\u0004\u0018\u000101X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b2\u00103\"\u0004\b4\u00105R\u001a\u00106\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b7\u0010\n\"\u0004\b8\u0010\fR\u0013\u0010\u0004\u001a\u0004\u0018\u00010\u0005¢\u0006\b\n\u0000\u001a\u0004\b9\u0010:R\u0011\u0010;\u001a\u00020\b8F¢\u0006\u0006\u001a\u0004\b<\u0010\nR\u0013\u0010=\u001a\u0004\u0018\u00010>8F¢\u0006\u0006\u001a\u0004\b?\u0010@R\u001a\u0010A\u001a\u00020BX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bC\u0010D\"\u0004\bE\u0010FR\u001a\u0010G\u001a\u00020BX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bH\u0010D\"\u0004\bI\u0010FR\u001a\u0010J\u001a\u00020BX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bK\u0010D\"\u0004\bL\u0010FR\u001a\u0010M\u001a\u00020BX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bN\u0010D\"\u0004\bO\u0010FR\u001a\u0010P\u001a\u00020BX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bQ\u0010D\"\u0004\bR\u0010FR\u001b\u0010S\u001a\u00020T8FX\u0086\u0084\u0002¢\u0006\f\n\u0004\bW\u0010\u0012\u001a\u0004\bU\u0010VR\u0011\u0010X\u001a\u00020B8F¢\u0006\u0006\u001a\u0004\bX\u0010DR\u0011\u0010Y\u001a\u00020B8F¢\u0006\u0006\u001a\u0004\bY\u0010DR\u001a\u0010Z\u001a\u00020BX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b[\u0010D\"\u0004\b\\\u0010FR\u001a\u0010]\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b^\u0010\n\"\u0004\b_\u0010\fR\u001a\u0010`\u001a\u00020BX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\ba\u0010D\"\u0004\bb\u0010FR\u001a\u0010c\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bd\u0010\n\"\u0004\be\u0010\fR\u001a\u0010f\u001a\u00020BX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bg\u0010D\"\u0004\bh\u0010FR\u0011\u0010i\u001a\u00020\b8F¢\u0006\u0006\u001a\u0004\bj\u0010\nR\u0011\u0010k\u001a\u00020\b8F¢\u0006\u0006\u001a\u0004\bl\u0010\nR\u0011\u0010m\u001a\u00020\b8F¢\u0006\u0006\u001a\u0004\bn\u0010\nR\u0011\u0010o\u001a\u00020\b8F¢\u0006\u0006\u001a\u0004\bp\u0010\nR\u0011\u0010q\u001a\u00020\b8F¢\u0006\u0006\u001a\u0004\br\u0010\nR\u0011\u0010s\u001a\u00020\b8F¢\u0006\u0006\u001a\u0004\bt\u0010\nR\u0011\u0010u\u001a\u00020B8F¢\u0006\u0006\u001a\u0004\bv\u0010DRe\u0010w\u001aI\u0012\u0013\u0012\u00110>¢\u0006\f\by\u0012\b\bz\u0012\u0004\b\b({\u0012\u0013\u0012\u00110|¢\u0006\f\by\u0012\b\bz\u0012\u0004\b\b(}\u0012\u0013\u0012\u00110\b¢\u0006\f\by\u0012\b\bz\u0012\u0004\b\b(~\u0012\u0006\u0012\u0004\u0018\u00010\u007f0xX\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b\u0080\u0001\u0010\u0081\u0001\"\u0006\b\u0082\u0001\u0010\u0083\u0001R\u001d\u0010\u0084\u0001\u001a\u00020\bX\u0086\u000e¢\u0006\u0010\n\u0000\u001a\u0005\b\u0085\u0001\u0010\n\"\u0005\b\u0086\u0001\u0010\fR\u001d\u0010\u0087\u0001\u001a\u00020\bX\u0086\u000e¢\u0006\u0010\n\u0000\u001a\u0005\b\u0088\u0001\u0010\n\"\u0005\b\u0089\u0001\u0010\fR-\u0010}\u001a\u0004\u0018\u00010|2\t\u0010\u008a\u0001\u001a\u0004\u0018\u00010|@FX\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b\u008b\u0001\u0010\u008c\u0001\"\u0006\b\u008d\u0001\u0010\u008e\u0001R!\u0010\u008f\u0001\u001a\u000f\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\u007f0\u0090\u0001¢\u0006\n\n\u0000\u001a\u0006\b\u0091\u0001\u0010\u0092\u0001R0\u0010\u0094\u0001\u001a\u0005\u0018\u00010\u0093\u00012\n\u0010\u008a\u0001\u001a\u0005\u0018\u00010\u0093\u0001@FX\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b\u0095\u0001\u0010\u0096\u0001\"\u0006\b\u0097\u0001\u0010\u0098\u0001R\"\u0010\u0099\u0001\u001a\u0005\u0018\u00010\u009a\u0001X\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b\u009b\u0001\u0010\u009c\u0001\"\u0006\b\u009d\u0001\u0010\u009e\u0001R\u001d\u0010\u009f\u0001\u001a\u00020\bX\u0086\u000e¢\u0006\u0010\n\u0000\u001a\u0005\b \u0001\u0010\n\"\u0005\b¡\u0001\u0010\fR0\u0010£\u0001\u001a\u0005\u0018\u00010¢\u00012\n\u0010\u008a\u0001\u001a\u0005\u0018\u00010¢\u0001@FX\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b¤\u0001\u0010¥\u0001\"\u0006\b¦\u0001\u0010§\u0001R\u001d\u0010¨\u0001\u001a\u00020BX\u0086\u000e¢\u0006\u0010\n\u0000\u001a\u0005\b©\u0001\u0010D\"\u0005\bª\u0001\u0010FR0\u0010¬\u0001\u001a\u0005\u0018\u00010«\u00012\n\u0010\u008a\u0001\u001a\u0005\u0018\u00010«\u0001@FX\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b\u00ad\u0001\u0010®\u0001\"\u0006\b¯\u0001\u0010°\u0001R,\u0010²\u0001\u001a\u00030±\u00012\b\u0010\u008a\u0001\u001a\u00030±\u0001@FX\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b³\u0001\u0010´\u0001\"\u0006\bµ\u0001\u0010¶\u0001R \u0010·\u0001\u001a\u00030¸\u0001X\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b¹\u0001\u0010º\u0001\"\u0006\b»\u0001\u0010¼\u0001R0\u0010¾\u0001\u001a\u0005\u0018\u00010½\u00012\n\u0010\u008a\u0001\u001a\u0005\u0018\u00010½\u0001@FX\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b¿\u0001\u0010À\u0001\"\u0006\bÁ\u0001\u0010Â\u0001¨\u0006¦\u0002"}, m5311d2 = {"Lcom/angcyo/tablayout/DslTabLayout;", "Landroid/view/ViewGroup;", "context", "Landroid/content/Context;", "attributeSet", "Landroid/util/AttributeSet;", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "_childAllWidthSum", "", "get_childAllWidthSum", "()I", "set_childAllWidthSum", "(I)V", "_gestureDetector", "Landroidx/core/view/GestureDetectorCompat;", "get_gestureDetector", "()Landroidx/core/view/GestureDetectorCompat;", "_gestureDetector$delegate", "Lkotlin/Lazy;", "_layoutDirection", "get_layoutDirection", "set_layoutDirection", "_maxConvexHeight", "get_maxConvexHeight", "set_maxConvexHeight", "_maxFlingVelocity", "get_maxFlingVelocity", "set_maxFlingVelocity", "_minFlingVelocity", "get_minFlingVelocity", "set_minFlingVelocity", "_overScroller", "Landroid/widget/OverScroller;", "get_overScroller", "()Landroid/widget/OverScroller;", "_overScroller$delegate", "_scrollAnimator", "Landroid/animation/ValueAnimator;", "get_scrollAnimator", "()Landroid/animation/ValueAnimator;", "_scrollAnimator$delegate", "_tempRect", "Landroid/graphics/Rect;", "get_tempRect", "()Landroid/graphics/Rect;", "_touchSlop", "get_touchSlop", "set_touchSlop", "_viewPagerDelegate", "Lcom/angcyo/tablayout/ViewPagerDelegate;", "get_viewPagerDelegate", "()Lcom/angcyo/tablayout/ViewPagerDelegate;", "set_viewPagerDelegate", "(Lcom/angcyo/tablayout/ViewPagerDelegate;)V", "_viewPagerScrollState", "get_viewPagerScrollState", "set_viewPagerScrollState", "getAttributeSet", "()Landroid/util/AttributeSet;", "currentItemIndex", "getCurrentItemIndex", "currentItemView", "Landroid/view/View;", "getCurrentItemView", "()Landroid/view/View;", "drawBadge", "", "getDrawBadge", "()Z", "setDrawBadge", "(Z)V", "drawBorder", "getDrawBorder", "setDrawBorder", "drawDivider", "getDrawDivider", "setDrawDivider", "drawHighlight", "getDrawHighlight", "setDrawHighlight", "drawIndicator", "getDrawIndicator", "setDrawIndicator", "dslSelector", "Lcom/angcyo/tablayout/DslSelector;", "getDslSelector", "()Lcom/angcyo/tablayout/DslSelector;", "dslSelector$delegate", "isAnimatorStart", "isLayoutRtl", "itemAutoEquWidth", "getItemAutoEquWidth", "setItemAutoEquWidth", "itemDefaultHeight", "getItemDefaultHeight", "setItemDefaultHeight", "itemIsEquWidth", "getItemIsEquWidth", "setItemIsEquWidth", "itemWidth", "getItemWidth", "setItemWidth", "layoutScrollAnim", "getLayoutScrollAnim", "setLayoutScrollAnim", "maxHeight", "getMaxHeight", "maxScrollX", "getMaxScrollX", "maxScrollY", "getMaxScrollY", "maxWidth", "getMaxWidth", "minScrollX", "getMinScrollX", "minScrollY", "getMinScrollY", "needScroll", "getNeedScroll", "onTabBadgeConfig", "Lkotlin/Function3;", "Lkotlin/ParameterName;", "name", "child", "Lcom/angcyo/tablayout/DslTabBadge;", "tabBadge", "index", "Lcom/angcyo/tablayout/TabBadgeConfig;", "getOnTabBadgeConfig", "()Lkotlin/jvm/functions/Function3;", "setOnTabBadgeConfig", "(Lkotlin/jvm/functions/Function3;)V", "orientation", "getOrientation", "setOrientation", "scrollAnimDuration", "getScrollAnimDuration", "setScrollAnimDuration", "value", "getTabBadge", "()Lcom/angcyo/tablayout/DslTabBadge;", "setTabBadge", "(Lcom/angcyo/tablayout/DslTabBadge;)V", "tabBadgeConfigMap", "", "getTabBadgeConfigMap", "()Ljava/util/Map;", "Lcom/angcyo/tablayout/DslTabBorder;", "tabBorder", "getTabBorder", "()Lcom/angcyo/tablayout/DslTabBorder;", "setTabBorder", "(Lcom/angcyo/tablayout/DslTabBorder;)V", "tabConvexBackgroundDrawable", "Landroid/graphics/drawable/Drawable;", "getTabConvexBackgroundDrawable", "()Landroid/graphics/drawable/Drawable;", "setTabConvexBackgroundDrawable", "(Landroid/graphics/drawable/Drawable;)V", "tabDefaultIndex", "getTabDefaultIndex", "setTabDefaultIndex", "Lcom/angcyo/tablayout/DslTabDivider;", "tabDivider", "getTabDivider", "()Lcom/angcyo/tablayout/DslTabDivider;", "setTabDivider", "(Lcom/angcyo/tablayout/DslTabDivider;)V", "tabEnableSelectorMode", "getTabEnableSelectorMode", "setTabEnableSelectorMode", "Lcom/angcyo/tablayout/DslTabHighlight;", "tabHighlight", "getTabHighlight", "()Lcom/angcyo/tablayout/DslTabHighlight;", "setTabHighlight", "(Lcom/angcyo/tablayout/DslTabHighlight;)V", "Lcom/angcyo/tablayout/DslTabIndicator;", "tabIndicator", "getTabIndicator", "()Lcom/angcyo/tablayout/DslTabIndicator;", "setTabIndicator", "(Lcom/angcyo/tablayout/DslTabIndicator;)V", "tabIndicatorAnimationDuration", "", "getTabIndicatorAnimationDuration", "()J", "setTabIndicatorAnimationDuration", "(J)V", "Lcom/angcyo/tablayout/DslTabLayoutConfig;", "tabLayoutConfig", "getTabLayoutConfig", "()Lcom/angcyo/tablayout/DslTabLayoutConfig;", "setTabLayoutConfig", "(Lcom/angcyo/tablayout/DslTabLayoutConfig;)V", "_animateToItem", "", "fromIndex", "toIndex", "_getViewTargetX", "_getViewTargetY", "_onAnimateEnd", "_onAnimateValue", "", "_scrollToTarget", "scrollAnim", "computeScroll", "configTabLayoutConfig", "config", "Lkotlin/Function1;", "Lkotlin/ExtensionFunctionType;", "draw", "canvas", "Landroid/graphics/Canvas;", "drawChild", "drawingTime", "generateDefaultLayoutParams", "Landroid/view/ViewGroup$LayoutParams;", "generateLayoutParams", "attrs", "p", "getBadgeConfig", "isHorizontal", "layoutHorizontal", "changed", "l", "t", "r", "b", "layoutVertical", "measureHorizontal", "widthMeasureSpec", "heightMeasureSpec", "measureVertical", "observeIndexChange", "action", "Lkotlin/Function4;", "reselect", "fromUser", "onAttachedToWindow", "onDetachedFromWindow", "onDraw", "onFinishInflate", "onFlingChange", "velocity", "onInterceptTouchEvent", "ev", "Landroid/view/MotionEvent;", "onLayout", "onMeasure", "onPageScrollStateChanged", "state", "onPageScrolled", "position", "positionOffset", "positionOffsetPixels", "onPageSelected", "onRestoreInstanceState", "Landroid/os/Parcelable;", "onRtlPropertiesChanged", "layoutDirection", "onSaveInstanceState", "onScrollChange", "distance", "onSizeChanged", "w", "h", "oldw", "oldh", "onTouchEvent", NotificationCompat.CATEGORY_EVENT, "onViewAdded", "onViewRemoved", "restoreScroll", "scrollTo", "x", "y", "setCurrentItem", "notify", "doIt", "setupViewPager", "viewPagerDelegate", "startFling", "min", "max", "startScroll", "dv", "updateTabBadge", "badgeText", "", "updateTabLayout", "verifyDrawable", "who", "LayoutParams", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public class DslTabLayout extends ViewGroup {

    /* renamed from: A */
    public boolean f8743A;

    /* renamed from: B */
    public int f8744B;

    /* renamed from: C */
    public int f8745C;

    /* renamed from: D */
    public int f8746D;

    /* renamed from: E */
    public int f8747E;

    /* renamed from: F */
    @NotNull
    public final Rect f8748F;

    /* renamed from: G */
    @NotNull
    public final Lazy f8749G;

    /* renamed from: H */
    public int f8750H;

    /* renamed from: I */
    public int f8751I;

    /* renamed from: J */
    public int f8752J;

    /* renamed from: K */
    @NotNull
    public final Lazy f8753K;

    /* renamed from: L */
    @NotNull
    public final Lazy f8754L;

    /* renamed from: M */
    @NotNull
    public final Lazy f8755M;

    /* renamed from: N */
    @Nullable
    public ViewPagerDelegate f8756N;

    /* renamed from: O */
    public int f8757O;

    /* renamed from: c */
    @Nullable
    public final AttributeSet f8758c;

    /* renamed from: e */
    public int f8759e;

    /* renamed from: f */
    public boolean f8760f;

    /* renamed from: g */
    public boolean f8761g;

    /* renamed from: h */
    public int f8762h;

    /* renamed from: i */
    public boolean f8763i;

    /* renamed from: j */
    @NotNull
    public DslTabIndicator f8764j;

    /* renamed from: k */
    public long f8765k;

    /* renamed from: l */
    public int f8766l;

    /* renamed from: m */
    @Nullable
    public DslTabLayoutConfig f8767m;

    /* renamed from: n */
    @Nullable
    public DslTabBorder f8768n;

    /* renamed from: o */
    public boolean f8769o;

    /* renamed from: p */
    @Nullable
    public DslTabDivider f8770p;

    /* renamed from: q */
    public boolean f8771q;

    /* renamed from: r */
    @Nullable
    public DslTabBadge f8772r;

    /* renamed from: s */
    public boolean f8773s;

    /* renamed from: t */
    @NotNull
    public final Map<Integer, TabBadgeConfig> f8774t;

    /* renamed from: u */
    @NotNull
    public Function3<? super View, ? super DslTabBadge, ? super Integer, TabBadgeConfig> f8775u;

    /* renamed from: v */
    public boolean f8776v;

    /* renamed from: w */
    @Nullable
    public DslTabHighlight f8777w;

    /* renamed from: x */
    @Nullable
    public Drawable f8778x;

    /* renamed from: y */
    public boolean f8779y;

    /* renamed from: z */
    public int f8780z;

    @Metadata(m5310d1 = {"\u0000\b\n\u0000\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0002\b\u0002"}, m5311d2 = {"<anonymous>", "Landroidx/core/view/GestureDetectorCompat;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.angcyo.tablayout.DslTabLayout$b */
    public static final class C3201b extends Lambda implements Function0<GestureDetectorCompat> {

        /* renamed from: c */
        public final /* synthetic */ Context f8788c;

        /* renamed from: e */
        public final /* synthetic */ DslTabLayout f8789e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3201b(Context context, DslTabLayout dslTabLayout) {
            super(0);
            this.f8788c = context;
            this.f8789e = dslTabLayout;
        }

        @Override // kotlin.jvm.functions.Function0
        public GestureDetectorCompat invoke() {
            return new GestureDetectorCompat(this.f8788c, new C1520q(this.f8789e));
        }
    }

    @Metadata(m5310d1 = {"\u0000\b\n\u0000\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0002\b\u0002"}, m5311d2 = {"<anonymous>", "Landroid/widget/OverScroller;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.angcyo.tablayout.DslTabLayout$c */
    public static final class C3202c extends Lambda implements Function0<OverScroller> {

        /* renamed from: c */
        public final /* synthetic */ Context f8790c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3202c(Context context) {
            super(0);
            this.f8790c = context;
        }

        @Override // kotlin.jvm.functions.Function0
        public OverScroller invoke() {
            return new OverScroller(this.f8790c);
        }
    }

    @Metadata(m5310d1 = {"\u0000\b\n\u0000\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0002\b\u0002"}, m5311d2 = {"<anonymous>", "Landroid/animation/ValueAnimator;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.angcyo.tablayout.DslTabLayout$d */
    public static final class C3203d extends Lambda implements Function0<ValueAnimator> {
        public C3203d() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public ValueAnimator invoke() {
            ValueAnimator valueAnimator = new ValueAnimator();
            final DslTabLayout dslTabLayout = DslTabLayout.this;
            valueAnimator.setInterpolator(new LinearInterpolator());
            valueAnimator.setDuration(dslTabLayout.getF8765k());
            valueAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: b.e.a.c
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public final void onAnimationUpdate(ValueAnimator valueAnimator2) {
                    DslTabLayout this$0 = DslTabLayout.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Object animatedValue = valueAnimator2.getAnimatedValue();
                    Objects.requireNonNull(animatedValue, "null cannot be cast to non-null type kotlin.Float");
                    this$0.m3864b(((Float) animatedValue).floatValue());
                }
            });
            valueAnimator.addListener(new C1521r(dslTabLayout));
            return valueAnimator;
        }
    }

    @Metadata(m5310d1 = {"\u0000\b\n\u0000\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0002\b\u0002"}, m5311d2 = {"<anonymous>", "Lcom/angcyo/tablayout/DslSelector;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.angcyo.tablayout.DslTabLayout$e */
    public static final class C3204e extends Lambda implements Function0<DslSelector> {
        public C3204e() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public DslSelector invoke() {
            DslSelector dslSelector = new DslSelector();
            DslTabLayout viewGroup = DslTabLayout.this;
            C1526w config = new C1526w(viewGroup);
            Intrinsics.checkNotNullParameter(viewGroup, "viewGroup");
            Intrinsics.checkNotNullParameter(config, "config");
            dslSelector.f1586h = -1;
            dslSelector.f1579a = viewGroup;
            dslSelector.m666i();
            config.invoke(dslSelector.f1580b);
            dslSelector.m665h();
            dslSelector.m664g();
            int size = dslSelector.f1581c.size();
            int i2 = dslSelector.f1586h;
            boolean z = false;
            if (i2 >= 0 && i2 < size) {
                z = true;
            }
            if (z) {
                dslSelector.m662d(i2, (r13 & 2) != 0, (r13 & 4) != 0, (r13 & 8) != 0 ? false : false, (r13 & 16) != 0 ? false : false);
            }
            return dslSelector;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u001a\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\n¢\u0006\u0002\b\b"}, m5311d2 = {"<anonymous>", "Lcom/angcyo/tablayout/TabBadgeConfig;", "<anonymous parameter 0>", "Landroid/view/View;", "tabBadge", "Lcom/angcyo/tablayout/DslTabBadge;", "index", "", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.angcyo.tablayout.DslTabLayout$f */
    public static final class C3205f extends Lambda implements Function3<View, DslTabBadge, Integer, TabBadgeConfig> {
        public C3205f() {
            super(3);
        }

        @Override // kotlin.jvm.functions.Function3
        public TabBadgeConfig invoke(View view, DslTabBadge dslTabBadge, Integer num) {
            TabBadgeConfig tabBadgeConfig;
            View noName_0 = view;
            DslTabBadge tabBadge = dslTabBadge;
            int intValue = num.intValue();
            Intrinsics.checkNotNullParameter(noName_0, "$noName_0");
            Intrinsics.checkNotNullParameter(tabBadge, "tabBadge");
            DslTabLayout dslTabLayout = DslTabLayout.this;
            TabBadgeConfig tabBadgeConfig2 = dslTabLayout.f8774t.get(Integer.valueOf(intValue));
            if (tabBadgeConfig2 == null) {
                DslTabBadge f8772r = dslTabLayout.getF8772r();
                tabBadgeConfig2 = null;
                if (f8772r != null && (tabBadgeConfig = f8772r.f1595H) != null) {
                    tabBadgeConfig2 = new TabBadgeConfig(tabBadgeConfig.f1682a, tabBadgeConfig.f1683b, tabBadgeConfig.f1684c, tabBadgeConfig.f1685d, tabBadgeConfig.f1686e, tabBadgeConfig.f1687f, tabBadgeConfig.f1688g, tabBadgeConfig.f1689h, tabBadgeConfig.f1690i, tabBadgeConfig.f1691j, tabBadgeConfig.f1692k, tabBadgeConfig.f1693l, tabBadgeConfig.f1694m, tabBadgeConfig.f1695n, tabBadgeConfig.f1696o, tabBadgeConfig.f1697p, tabBadgeConfig.f1698q, tabBadgeConfig.f1699r, tabBadgeConfig.f1700s, tabBadgeConfig.f1701t, tabBadgeConfig.f1702u);
                }
                if (tabBadgeConfig2 == null) {
                    tabBadgeConfig2 = new TabBadgeConfig(null, 0, 0, 0, 0, 0, 0.0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0, 0, 2097151);
                }
            }
            TabBadgeConfig badgeConfig = tabBadgeConfig2;
            if (!DslTabLayout.this.isInEditMode()) {
                Objects.requireNonNull(tabBadge);
                Intrinsics.checkNotNullParameter(badgeConfig, "badgeConfig");
                tabBadge.f1554c = badgeConfig.f1684c;
                tabBadge.f1555d = badgeConfig.f1685d;
                tabBadge.f1556e = badgeConfig.f1686e;
                tabBadge.f1538s = badgeConfig.f1687f;
                tabBadge.f1537r = badgeConfig.f1683b;
                tabBadge.f1545z = badgeConfig.f1691j;
                tabBadge.f1529A = badgeConfig.f1692k;
                tabBadge.f1543x = badgeConfig.f1693l;
                tabBadge.f1544y = badgeConfig.f1694m;
                tabBadge.f1542w = badgeConfig.f1689h;
                tabBadge.f1530B = badgeConfig.f1695n;
                tabBadge.f1531C = badgeConfig.f1696o;
                tabBadge.f1532D = badgeConfig.f1697p;
                tabBadge.f1533E = badgeConfig.f1698q;
                tabBadge.f1540u = badgeConfig.f1688g;
                tabBadge.m649f().setTextSize(tabBadge.f1540u);
                Arrays.fill(tabBadge.f1559h, badgeConfig.f1690i);
                tabBadge.f1534F = badgeConfig.f1701t;
                tabBadge.f1535G = badgeConfig.f1702u;
                tabBadge.f1539t = badgeConfig.f1682a;
            }
            return badgeConfig;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DslTabLayout(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        this.f8758c = attributeSet;
        Intrinsics.checkNotNullParameter(this, "<this>");
        this.f8759e = ((int) getContext().getResources().getDisplayMetrics().density) * 40;
        this.f8762h = -3;
        this.f8763i = true;
        this.f8764j = new DslTabIndicator(this);
        this.f8765k = 240L;
        this.f8774t = new LinkedHashMap();
        this.f8775u = new C3205f();
        this.f8744B = 250;
        this.f8748F = new Rect();
        this.f8749G = LazyKt__LazyJVMKt.lazy(new C3204e());
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.DslTabLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr…R.styleable.DslTabLayout)");
        this.f8760f = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_item_is_equ_width, this.f8760f);
        this.f8761g = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_item_auto_equ_width, this.f8761g);
        this.f8762h = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_item_width, this.f8762h);
        this.f8759e = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_item_default_height, this.f8759e);
        this.f8766l = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_default_index, this.f8766l);
        this.f8763i = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_draw_indicator, this.f8763i);
        this.f8771q = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_draw_divider, this.f8771q);
        this.f8769o = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_draw_border, this.f8769o);
        this.f8773s = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_draw_badge, this.f8773s);
        this.f8776v = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_draw_highlight, this.f8776v);
        this.f8779y = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_selector_mode, this.f8779y);
        this.f8778x = obtainStyledAttributes.getDrawable(R$styleable.DslTabLayout_tab_convex_background);
        this.f8780z = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_orientation, this.f8780z);
        this.f8743A = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_layout_scroll_anim, this.f8743A);
        this.f8744B = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_scroll_anim_duration, this.f8744B);
        obtainStyledAttributes.recycle();
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        this.f8745C = viewConfiguration.getScaledMinimumFlingVelocity();
        this.f8746D = viewConfiguration.getScaledMaximumFlingVelocity();
        if (this.f8763i) {
            this.f8764j.m680u(context, attributeSet);
        }
        if (this.f8769o) {
            setTabBorder(new DslTabBorder());
        }
        if (this.f8771q) {
            setTabDivider(new DslTabDivider());
        }
        if (this.f8773s) {
            setTabBadge(new DslTabBadge());
        }
        if (this.f8776v) {
            setTabHighlight(new DslTabHighlight(this));
        }
        setTabLayoutConfig(new DslTabLayoutConfig(this));
        setWillNotDraw(false);
        this.f8752J = -1;
        this.f8753K = LazyKt__LazyJVMKt.lazy(new C3202c(context));
        this.f8754L = LazyKt__LazyJVMKt.lazy(new C3201b(context, this));
        this.f8755M = LazyKt__LazyJVMKt.lazy(new C3203d());
    }

    /* renamed from: h */
    public static final void m3860h(DslTabLayout dslTabLayout, Ref.IntRef intRef, Ref.IntRef intRef2, Ref.BooleanRef booleanRef, Ref.IntRef intRef3, Ref.IntRef intRef4, View view) {
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type com.angcyo.tablayout.DslTabLayout.LayoutParams");
        C3200a c3200a = (C3200a) layoutParams;
        ((FrameLayout.LayoutParams) c3200a).topMargin = 0;
        ((FrameLayout.LayoutParams) c3200a).bottomMargin = 0;
        int i2 = c3200a.f8783c;
        int[] m4759C = C4195m.m4759C(dslTabLayout, c3200a.f8781a, c3200a.f8782b, intRef.element, intRef2.element, 0, 0);
        booleanRef.element = false;
        if (intRef3.element == -1 && m4759C[1] > 0) {
            int i3 = m4759C[1];
            intRef2.element = i3;
            intRef3.element = C4195m.m4790W(i3);
            intRef2.element = dslTabLayout.getPaddingBottom() + dslTabLayout.getPaddingTop() + intRef2.element;
        }
        if (intRef3.element == -1) {
            if (((FrameLayout.LayoutParams) c3200a).height == -1) {
                int suggestedMinimumHeight = dslTabLayout.getSuggestedMinimumHeight() > 0 ? dslTabLayout.getSuggestedMinimumHeight() : dslTabLayout.f8759e;
                intRef2.element = suggestedMinimumHeight;
                intRef3.element = C4195m.m4790W(suggestedMinimumHeight);
                intRef2.element = dslTabLayout.getPaddingBottom() + dslTabLayout.getPaddingTop() + intRef2.element;
            } else {
                intRef3.element = C4195m.m4834u(intRef2.element);
                booleanRef.element = true;
            }
        }
        int i4 = intRef4.element;
        if (i2 > 0) {
            dslTabLayout.f8751I = Math.max(dslTabLayout.f8751I, i2);
            view.measure(intRef4.element, View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(intRef3.element) + i2, View.MeasureSpec.getMode(intRef3.element)));
        } else {
            view.measure(i4, intRef3.element);
        }
        if (booleanRef.element) {
            int measuredHeight = view.getMeasuredHeight();
            intRef2.element = measuredHeight;
            intRef3.element = C4195m.m4790W(measuredHeight);
            intRef2.element = dslTabLayout.getPaddingBottom() + dslTabLayout.getPaddingTop() + intRef2.element;
        }
    }

    /* renamed from: i */
    public static final void m3861i(DslTabLayout dslTabLayout, Ref.IntRef intRef, Ref.IntRef intRef2, Ref.BooleanRef booleanRef, Ref.IntRef intRef3, Ref.IntRef intRef4, View view) {
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type com.angcyo.tablayout.DslTabLayout.LayoutParams");
        C3200a c3200a = (C3200a) layoutParams;
        c3200a.setMarginStart(0);
        c3200a.setMarginEnd(0);
        int i2 = c3200a.f8783c;
        int[] m4759C = C4195m.m4759C(dslTabLayout, c3200a.f8781a, c3200a.f8782b, intRef.element, intRef2.element, 0, 0);
        booleanRef.element = false;
        if (intRef3.element == -1 && m4759C[0] > 0) {
            int i3 = m4759C[0];
            intRef.element = i3;
            intRef3.element = C4195m.m4790W(i3);
            intRef.element = dslTabLayout.getPaddingEnd() + dslTabLayout.getPaddingStart() + intRef.element;
        }
        if (intRef3.element == -1) {
            if (((FrameLayout.LayoutParams) c3200a).width == -1) {
                int suggestedMinimumWidth = dslTabLayout.getSuggestedMinimumWidth() > 0 ? dslTabLayout.getSuggestedMinimumWidth() : dslTabLayout.f8759e;
                intRef.element = suggestedMinimumWidth;
                intRef3.element = C4195m.m4790W(suggestedMinimumWidth);
                intRef.element = dslTabLayout.getPaddingEnd() + dslTabLayout.getPaddingStart() + intRef.element;
            } else {
                intRef3.element = C4195m.m4834u(intRef.element);
                booleanRef.element = true;
            }
        }
        int i4 = intRef4.element;
        if (i2 > 0) {
            dslTabLayout.f8751I = Math.max(dslTabLayout.f8751I, i2);
            view.measure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(intRef3.element) + i2, View.MeasureSpec.getMode(intRef3.element)), intRef4.element);
        } else {
            view.measure(intRef3.element, i4);
        }
        if (booleanRef.element) {
            int measuredWidth = view.getMeasuredWidth();
            intRef.element = measuredWidth;
            intRef3.element = C4195m.m4790W(measuredWidth);
            intRef.element = dslTabLayout.getPaddingEnd() + dslTabLayout.getPaddingStart() + intRef.element;
        }
    }

    /* renamed from: o */
    public static /* synthetic */ void m3862o(DslTabLayout dslTabLayout, int i2, boolean z, boolean z2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            z = true;
        }
        if ((i3 & 4) != 0) {
            z2 = false;
        }
        dslTabLayout.m3874n(i2, z, z2);
    }

    /* renamed from: a */
    public final void m3863a() {
        this.f8764j.f1632K = getDslSelector().f1586h;
        DslTabIndicator dslTabIndicator = this.f8764j;
        dslTabIndicator.f1633L = dslTabIndicator.f1632K;
        dslTabIndicator.f1631J = 0.0f;
        dslTabIndicator.invalidateSelf();
    }

    /* renamed from: b */
    public final void m3864b(float f2) {
        DslTabIndicator dslTabIndicator = this.f8764j;
        dslTabIndicator.f1631J = f2;
        dslTabIndicator.invalidateSelf();
        DslTabLayoutConfig dslTabLayoutConfig = this.f8767m;
        if (dslTabLayoutConfig != null) {
            int i2 = this.f8764j.f1632K;
        }
        if (dslTabLayoutConfig == null) {
            return;
        }
        List<View> list = getDslSelector().f1581c;
        View toView = (View) CollectionsKt___CollectionsKt.getOrNull(list, getF8764j().f1633L);
        if (toView != null) {
            View view = (View) CollectionsKt___CollectionsKt.getOrNull(list, getF8764j().f1632K);
            Intrinsics.checkNotNullParameter(toView, "toView");
            if (Intrinsics.areEqual(view, toView)) {
                return;
            }
            int i3 = dslTabLayoutConfig.f1655e.getF8764j().f1632K;
            int i4 = dslTabLayoutConfig.f1655e.getF8764j().f1633L;
            if (dslTabLayoutConfig.f1658h) {
                int intValue = dslTabLayoutConfig.f1654A.invoke(Integer.valueOf(i3), Integer.valueOf(i3), Float.valueOf(0.0f)).intValue();
                int intValue2 = dslTabLayoutConfig.f1654A.invoke(Integer.valueOf(i3), Integer.valueOf(i4), Float.valueOf(f2)).intValue();
                DslTabIndicator f8764j = dslTabLayoutConfig.f1655e.getF8764j();
                f8764j.f1642z = C4195m.m4789V(f2, intValue, intValue2);
                f8764j.m681v(f8764j.f1641y);
            }
            if (dslTabLayoutConfig.f1657g) {
                if (view != null) {
                    dslTabLayoutConfig.m683a(dslTabLayoutConfig.f1675y.invoke(view, Integer.valueOf(i3)), dslTabLayoutConfig.f1659i, dslTabLayoutConfig.f1660j, f2);
                }
                dslTabLayoutConfig.m683a(dslTabLayoutConfig.f1675y.invoke(toView, Integer.valueOf(i4)), dslTabLayoutConfig.f1660j, dslTabLayoutConfig.f1659i, f2);
            }
            if (dslTabLayoutConfig.f1663m) {
                if (view != null) {
                    View invoke = dslTabLayoutConfig.f1676z.invoke(view, Integer.valueOf(i3));
                    int m685c = dslTabLayoutConfig.m685c();
                    int m684b = dslTabLayoutConfig.m684b();
                    TabGradientCallback tabGradientCallback = dslTabLayoutConfig.f1672v;
                    Objects.requireNonNull(tabGradientCallback);
                    tabGradientCallback.m641a(invoke, C4195m.m4789V(f2, m685c, m684b));
                }
                View invoke2 = dslTabLayoutConfig.f1676z.invoke(toView, Integer.valueOf(i4));
                int m684b2 = dslTabLayoutConfig.m684b();
                int m685c2 = dslTabLayoutConfig.m685c();
                TabGradientCallback tabGradientCallback2 = dslTabLayoutConfig.f1672v;
                Objects.requireNonNull(tabGradientCallback2);
                tabGradientCallback2.m641a(invoke2, C4195m.m4789V(f2, m684b2, m685c2));
            }
            if (dslTabLayoutConfig.f1666p) {
                float f3 = dslTabLayoutConfig.f1668r;
                float f4 = dslTabLayoutConfig.f1667q;
                Objects.requireNonNull(dslTabLayoutConfig.f1672v);
                if (view != null) {
                    float f5 = ((f4 - f3) * f2) + f3;
                    view.setScaleX(f5);
                    view.setScaleY(f5);
                }
                float f6 = dslTabLayoutConfig.f1667q;
                float f7 = dslTabLayoutConfig.f1668r;
                Objects.requireNonNull(dslTabLayoutConfig.f1672v);
                float f8 = ((f7 - f6) * f2) + f6;
                toView.setScaleX(f8);
                toView.setScaleY(f8);
            }
            if (dslTabLayoutConfig.f1669s) {
                float f9 = dslTabLayoutConfig.f1671u;
                if (f9 > 0.0f) {
                    float f10 = dslTabLayoutConfig.f1670t;
                    if (f10 > 0.0f) {
                        if (f10 == f9) {
                            return;
                        }
                        TextView invoke3 = view == null ? null : dslTabLayoutConfig.f1675y.invoke(view, Integer.valueOf(i3));
                        float f11 = dslTabLayoutConfig.f1671u;
                        float f12 = dslTabLayoutConfig.f1670t;
                        Objects.requireNonNull(dslTabLayoutConfig.f1672v);
                        if (invoke3 != null) {
                            invoke3.setTextSize(0, ((f12 - f11) * f2) + f11);
                        }
                        TextView invoke4 = dslTabLayoutConfig.f1675y.invoke(toView, Integer.valueOf(i4));
                        float f13 = dslTabLayoutConfig.f1670t;
                        float f14 = dslTabLayoutConfig.f1671u;
                        Objects.requireNonNull(dslTabLayoutConfig.f1672v);
                        if (invoke4 != null) {
                            invoke4.setTextSize(0, ((f14 - f13) * f2) + f13);
                        }
                        if (i4 == CollectionsKt__CollectionsKt.getLastIndex(dslTabLayoutConfig.f1655e.getDslSelector().f1581c) || i4 == 0) {
                            dslTabLayoutConfig.f1655e.m3865c(i4, false);
                        }
                    }
                }
            }
        }
    }

    /* renamed from: c */
    public final void m3865c(int i2, boolean z) {
        int paddingTop;
        int scrollY;
        int i3;
        int scrollY2;
        int i4;
        int paddingStart;
        if (getNeedScroll()) {
            View view = (View) CollectionsKt___CollectionsKt.getOrNull(getDslSelector().f1581c, i2);
            if (view == null || ViewCompat.isLaidOut(view)) {
                if (m3866d()) {
                    DslTabIndicator dslTabIndicator = this.f8764j;
                    int i5 = DslTabIndicator.f1621q;
                    int m675p = dslTabIndicator.m675p(i2, dslTabIndicator.f1636t);
                    int i6 = this.f8764j.f1636t;
                    if (i6 == 1) {
                        paddingStart = getPaddingStart();
                    } else if (i6 != 2) {
                        paddingStart = (C4195m.m4819m0(this) / 2) + getPaddingStart();
                    } else {
                        paddingStart = getMeasuredWidth() - getPaddingEnd();
                    }
                    if (this.f8779y) {
                        i3 = m675p - (getMeasuredWidth() / 2);
                        scrollY2 = getScrollX();
                    } else if (m3867e()) {
                        if (m675p < paddingStart) {
                            i3 = m675p - paddingStart;
                            scrollY2 = getScrollX();
                        } else {
                            scrollY = getScrollX();
                            i4 = -scrollY;
                        }
                    } else if (m675p > paddingStart) {
                        i3 = m675p - paddingStart;
                        scrollY2 = getScrollX();
                    } else {
                        scrollY = getScrollX();
                        i4 = -scrollY;
                    }
                    i4 = i3 - scrollY2;
                } else {
                    DslTabIndicator dslTabIndicator2 = this.f8764j;
                    int i7 = DslTabIndicator.f1621q;
                    int m676q = dslTabIndicator2.m676q(i2, dslTabIndicator2.f1636t);
                    int i8 = this.f8764j.f1636t;
                    if (i8 == 1) {
                        paddingTop = getPaddingTop();
                    } else if (i8 != 2) {
                        paddingTop = (C4195m.m4817l0(this) / 2) + getPaddingTop();
                    } else {
                        paddingTop = getMeasuredHeight() - getPaddingBottom();
                    }
                    if (this.f8779y) {
                        i3 = m676q - (getMeasuredHeight() / 2);
                        scrollY2 = getScrollY();
                    } else if (m676q > paddingTop) {
                        i3 = m676q - paddingTop;
                        scrollY2 = getScrollY();
                    } else if (this.f8764j.f1636t != 2 || m676q >= paddingTop) {
                        scrollY = getScrollY();
                        i4 = -scrollY;
                    } else {
                        i3 = m676q - paddingTop;
                        scrollY2 = getScrollY();
                    }
                    i4 = i3 - scrollY2;
                }
                if (m3866d()) {
                    if (!isInEditMode() && z) {
                        m3876q(i4);
                        return;
                    } else {
                        get_overScroller().abortAnimation();
                        scrollBy(i4, 0);
                        return;
                    }
                }
                if (!isInEditMode() && z) {
                    m3876q(i4);
                } else {
                    get_overScroller().abortAnimation();
                    scrollBy(0, i4);
                }
            }
        }
    }

    @Override // android.view.View
    public void computeScroll() {
        if (get_overScroller().computeScrollOffset()) {
            scrollTo(get_overScroller().getCurrX(), get_overScroller().getCurrY());
            invalidate();
            if (get_overScroller().getCurrX() < getMinScrollX() || get_overScroller().getCurrX() > getMaxScrollX()) {
                get_overScroller().abortAnimation();
            }
        }
    }

    /* renamed from: d */
    public final boolean m3866d() {
        return this.f8780z == 0;
    }

    @Override // android.view.View
    public void draw(@NotNull Canvas canvas) {
        DslTabBadge dslTabBadge;
        int left;
        int top;
        int right;
        int bottom;
        int i2;
        DslTabBorder dslTabBorder;
        DslTabHighlight dslTabHighlight;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        if (this.f8763i) {
            this.f8764j.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
        }
        Drawable drawable = this.f8778x;
        if (drawable != null) {
            if (m3866d()) {
                drawable.setBounds(0, getF8751I(), getRight() - getLeft(), getBottom() - getTop());
            } else {
                drawable.setBounds(0, 0, getMeasuredWidth() - getF8751I(), getBottom() - getTop());
            }
            if ((getScrollX() | getScrollY()) == 0) {
                drawable.draw(canvas);
            } else {
                canvas.translate(getScrollX(), getScrollY());
                drawable.draw(canvas);
                canvas.translate(-getScrollX(), -getScrollY());
            }
        }
        super.draw(canvas);
        if (this.f8776v && (dslTabHighlight = this.f8777w) != null) {
            dslTabHighlight.draw(canvas);
        }
        int size = getDslSelector().f1581c.size();
        if (this.f8771q) {
            if (!m3866d()) {
                DslTabDivider dslTabDivider = this.f8770p;
                if (dslTabDivider != null) {
                    int paddingStart = getPaddingStart() + dslTabDivider.f1610s;
                    int measuredWidth = (getMeasuredWidth() - getPaddingEnd()) - dslTabDivider.f1611t;
                    int i3 = 0;
                    for (Object obj : getDslSelector().f1581c) {
                        int i4 = i3 + 1;
                        if (i3 < 0) {
                            CollectionsKt__CollectionsKt.throwIndexOverflow();
                        }
                        View view = (View) obj;
                        if (dslTabDivider.m670n(i3)) {
                            int top2 = view.getTop() - dslTabDivider.f1613v;
                            int i5 = dslTabDivider.f1609r;
                            int i6 = top2 - i5;
                            dslTabDivider.setBounds(paddingStart, i6, measuredWidth, i5 + i6);
                            dslTabDivider.draw(canvas);
                        }
                        if (dslTabDivider.m669m(i3, size)) {
                            int bottom2 = view.getBottom() + dslTabDivider.f1612u;
                            dslTabDivider.setBounds(paddingStart, bottom2, measuredWidth, dslTabDivider.f1609r + bottom2);
                            dslTabDivider.draw(canvas);
                        }
                        i3 = i4;
                    }
                }
            } else if (m3867e()) {
                DslTabDivider dslTabDivider2 = this.f8770p;
                if (dslTabDivider2 != null) {
                    int m648e = dslTabDivider2.m648e() + dslTabDivider2.f1612u;
                    int measuredHeight = (getMeasuredHeight() - dslTabDivider2.m645b()) - dslTabDivider2.f1613v;
                    int i7 = 0;
                    for (Object obj2 : getDslSelector().f1581c) {
                        int i8 = i7 + 1;
                        if (i7 < 0) {
                            CollectionsKt__CollectionsKt.throwIndexOverflow();
                        }
                        View view2 = (View) obj2;
                        if (dslTabDivider2.m670n(i7)) {
                            int right2 = view2.getRight() + dslTabDivider2.f1610s;
                            int i9 = dslTabDivider2.f1608q;
                            int i10 = right2 + i9;
                            dslTabDivider2.setBounds(i10 - i9, m648e, i10, measuredHeight);
                            dslTabDivider2.draw(canvas);
                        }
                        if (dslTabDivider2.m669m(i7, size)) {
                            int right3 = (view2.getRight() - view2.getMeasuredWidth()) - dslTabDivider2.f1611t;
                            dslTabDivider2.setBounds(right3 - dslTabDivider2.f1608q, m648e, right3, measuredHeight);
                            dslTabDivider2.draw(canvas);
                        }
                        i7 = i8;
                    }
                }
            } else {
                DslTabDivider dslTabDivider3 = this.f8770p;
                if (dslTabDivider3 != null) {
                    int m648e2 = dslTabDivider3.m648e() + dslTabDivider3.f1612u;
                    int measuredHeight2 = (getMeasuredHeight() - dslTabDivider3.m645b()) - dslTabDivider3.f1613v;
                    int i11 = 0;
                    for (Object obj3 : getDslSelector().f1581c) {
                        int i12 = i11 + 1;
                        if (i11 < 0) {
                            CollectionsKt__CollectionsKt.throwIndexOverflow();
                        }
                        View view3 = (View) obj3;
                        if (dslTabDivider3.m670n(i11)) {
                            int left2 = view3.getLeft() - dslTabDivider3.f1611t;
                            int i13 = dslTabDivider3.f1608q;
                            int i14 = left2 - i13;
                            dslTabDivider3.setBounds(i14, m648e2, i13 + i14, measuredHeight2);
                            dslTabDivider3.draw(canvas);
                        }
                        if (dslTabDivider3.m669m(i11, size)) {
                            int right4 = view3.getRight() + dslTabDivider3.f1610s;
                            dslTabDivider3.setBounds(right4, m648e2, dslTabDivider3.f1608q + right4, measuredHeight2);
                            dslTabDivider3.draw(canvas);
                        }
                        i11 = i12;
                    }
                }
            }
        }
        if (this.f8769o && (dslTabBorder = this.f8768n) != null) {
            dslTabBorder.draw(canvas);
        }
        if (this.f8763i) {
            DslTabIndicator dslTabIndicator = this.f8764j;
            if (dslTabIndicator.f1635s > 4096) {
                dslTabIndicator.draw(canvas);
            }
        }
        if (!this.f8773s || (dslTabBadge = this.f8772r) == null) {
            return;
        }
        int i15 = 0;
        for (Object obj4 : getDslSelector().f1581c) {
            int i16 = i15 + 1;
            if (i15 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            View view4 = (View) obj4;
            TabBadgeConfig invoke = getOnTabBadgeConfig().invoke(view4, dslTabBadge, Integer.valueOf(i15));
            if (invoke == null || (i2 = invoke.f1699r) < 0) {
                left = view4.getLeft();
                top = view4.getTop();
                right = view4.getRight();
                bottom = view4.getBottom();
            } else {
                View m4795a0 = C4195m.m4795a0(view4, i2);
                if (m4795a0 != null) {
                    view4 = m4795a0;
                }
                Rect result = getF8748F();
                Intrinsics.checkNotNullParameter(view4, "<this>");
                Intrinsics.checkNotNullParameter(result, "result");
                result.set(0, 0, 0, 0);
                if (!Intrinsics.areEqual(view4, this)) {
                    C4195m.m4805f0(view4, this, result);
                }
                result.right = view4.getMeasuredWidth() + result.left;
                result.bottom = view4.getMeasuredHeight() + result.top;
                left = getF8748F().left;
                top = getF8748F().top;
                right = getF8748F().right;
                bottom = getF8748F().bottom;
            }
            if (invoke != null && invoke.f1700s) {
                left += view4.getPaddingStart();
                top += view4.getPaddingTop();
                right -= view4.getPaddingEnd();
                bottom -= view4.getPaddingBottom();
            }
            dslTabBadge.setBounds(left, top, right, bottom);
            dslTabBadge.mo657k();
            View m644a = dslTabBadge.m644a();
            if (m644a == null ? false : m644a.isInEditMode()) {
                dslTabBadge.f1539t = i15 == size + (-1) ? "" : dslTabBadge.f1596I;
            }
            dslTabBadge.draw(canvas);
            i15 = i16;
        }
    }

    @Override // android.view.ViewGroup
    public boolean drawChild(@NotNull Canvas canvas, @NotNull View child, long drawingTime) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(child, "child");
        return super.drawChild(canvas, child, drawingTime);
    }

    /* renamed from: e */
    public final boolean m3867e() {
        return ViewCompat.getLayoutDirection(this) == 1;
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0077, code lost:
    
        if (r11.m670n(r7) == true) goto L26;
     */
    /* renamed from: f */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m3868f() {
        /*
            Method dump skipped, instructions count: 285
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.angcyo.tablayout.DslTabLayout.m3868f():void");
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0062  */
    /* renamed from: g */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m3869g() {
        /*
            r11 = this;
            int r0 = r11.getPaddingTop()
            r11.getPaddingStart()
            boolean r1 = r11.f8771q
            r2 = 0
            if (r1 == 0) goto L1a
            b.e.a.n r1 = r11.f8770p
            if (r1 != 0) goto L11
            goto L1a
        L11:
            int r3 = r1.f1609r
            int r4 = r1.f1612u
            int r3 = r3 + r4
            int r1 = r1.f1613v
            int r3 = r3 + r1
            goto L1b
        L1a:
            r3 = 0
        L1b:
            b.e.a.h r1 = r11.getDslSelector()
            java.util.List<android.view.View> r1 = r1.f1581c
            java.util.Iterator r4 = r1.iterator()
            r5 = 0
        L26:
            boolean r6 = r4.hasNext()
            if (r6 == 0) goto La9
            java.lang.Object r6 = r4.next()
            int r7 = r5 + 1
            if (r5 >= 0) goto L37
            kotlin.collections.CollectionsKt__CollectionsKt.throwIndexOverflow()
        L37:
            android.view.View r6 = (android.view.View) r6
            android.view.ViewGroup$LayoutParams r8 = r6.getLayoutParams()
            java.lang.String r9 = "null cannot be cast to non-null type com.angcyo.tablayout.DslTabLayout.LayoutParams"
            java.util.Objects.requireNonNull(r8, r9)
            com.angcyo.tablayout.DslTabLayout$a r8 = (com.angcyo.tablayout.DslTabLayout.C3200a) r8
            int r9 = r8.topMargin
            int r0 = r0 + r9
            boolean r9 = r11.getF8771q()
            r10 = 1
            if (r9 == 0) goto L63
            b.e.a.n r9 = r11.getF8770p()
            if (r9 != 0) goto L56
        L54:
            r5 = 0
            goto L60
        L56:
            r1.size()
            boolean r5 = r9.m670n(r5)
            if (r5 != r10) goto L54
            r5 = 1
        L60:
            if (r5 == 0) goto L63
            int r0 = r0 + r3
        L63:
            int r5 = r8.gravity
            boolean r5 = p403d.p404a.p405a.p407b.p408a.C4195m.m4823o0(r5, r10)
            if (r5 == 0) goto L8d
            int r5 = r11.getPaddingStart()
            int r9 = r11.getMeasuredWidth()
            int r10 = r11.getPaddingStart()
            int r9 = r9 - r10
            int r10 = r11.getPaddingEnd()
            int r9 = r9 - r10
            int r10 = r11.getF8751I()
            int r9 = r9 - r10
            int r9 = r9 / 2
            int r10 = r6.getMeasuredWidth()
            int r10 = r10 / 2
            int r9 = r9 - r10
            int r9 = r9 + r5
            goto L91
        L8d:
            int r9 = r11.getPaddingStart()
        L91:
            int r5 = r6.getMeasuredWidth()
            int r5 = r5 + r9
            int r10 = r6.getMeasuredHeight()
            int r10 = r10 + r0
            r6.layout(r9, r0, r5, r10)
            int r5 = r6.getMeasuredHeight()
            int r6 = r8.bottomMargin
            int r5 = r5 + r6
            int r0 = r0 + r5
            r5 = r7
            goto L26
        La9:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.angcyo.tablayout.DslTabLayout.m3869g():void");
    }

    @Override // android.view.ViewGroup
    @NotNull
    public ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new C3200a(-2, -2, 17);
    }

    @Override // android.view.ViewGroup
    @NotNull
    public ViewGroup.LayoutParams generateLayoutParams(@Nullable AttributeSet attrs) {
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        return new C3200a(context, attrs);
    }

    @Nullable
    /* renamed from: getAttributeSet, reason: from getter */
    public final AttributeSet getF8758c() {
        return this.f8758c;
    }

    public final int getCurrentItemIndex() {
        return getDslSelector().f1586h;
    }

    @Nullable
    public final View getCurrentItemView() {
        return (View) CollectionsKt___CollectionsKt.getOrNull(getDslSelector().f1581c, getCurrentItemIndex());
    }

    /* renamed from: getDrawBadge, reason: from getter */
    public final boolean getF8773s() {
        return this.f8773s;
    }

    /* renamed from: getDrawBorder, reason: from getter */
    public final boolean getF8769o() {
        return this.f8769o;
    }

    /* renamed from: getDrawDivider, reason: from getter */
    public final boolean getF8771q() {
        return this.f8771q;
    }

    /* renamed from: getDrawHighlight, reason: from getter */
    public final boolean getF8776v() {
        return this.f8776v;
    }

    /* renamed from: getDrawIndicator, reason: from getter */
    public final boolean getF8763i() {
        return this.f8763i;
    }

    @NotNull
    public final DslSelector getDslSelector() {
        return (DslSelector) this.f8749G.getValue();
    }

    /* renamed from: getItemAutoEquWidth, reason: from getter */
    public final boolean getF8761g() {
        return this.f8761g;
    }

    /* renamed from: getItemDefaultHeight, reason: from getter */
    public final int getF8759e() {
        return this.f8759e;
    }

    /* renamed from: getItemIsEquWidth, reason: from getter */
    public final boolean getF8760f() {
        return this.f8760f;
    }

    /* renamed from: getItemWidth, reason: from getter */
    public final int getF8762h() {
        return this.f8762h;
    }

    /* renamed from: getLayoutScrollAnim, reason: from getter */
    public final boolean getF8743A() {
        return this.f8743A;
    }

    public final int getMaxHeight() {
        return getPaddingBottom() + getPaddingTop() + this.f8750H;
    }

    public final int getMaxScrollX() {
        if (!m3867e() || !m3866d()) {
            return Math.max((getMaxWidth() - getMeasuredWidth()) + (this.f8779y ? C4195m.m4819m0(this) / 2 : 0), 0);
        }
        if (this.f8779y) {
            return C4195m.m4819m0(this) / 2;
        }
        return 0;
    }

    public final int getMaxScrollY() {
        return Math.max((getMaxHeight() - getMeasuredHeight()) + (this.f8779y ? C4195m.m4817l0(this) / 2 : 0), 0);
    }

    public final int getMaxWidth() {
        return getPaddingEnd() + getPaddingStart() + this.f8750H;
    }

    public final int getMinScrollX() {
        if (m3867e() && m3866d()) {
            return Math.min(-((getMaxWidth() - getMeasuredWidth()) + (this.f8779y ? C4195m.m4819m0(this) / 2 : 0)), 0);
        }
        if (this.f8779y) {
            return (-C4195m.m4819m0(this)) / 2;
        }
        return 0;
    }

    public final int getMinScrollY() {
        if (this.f8779y) {
            return (-C4195m.m4817l0(this)) / 2;
        }
        return 0;
    }

    public final boolean getNeedScroll() {
        if (!this.f8779y) {
            if (m3866d()) {
                if (m3867e()) {
                    if (getMinScrollX() >= 0) {
                        return false;
                    }
                } else if (getMaxScrollX() <= 0) {
                    return false;
                }
            } else if (getMaxScrollY() <= 0) {
                return false;
            }
        }
        return true;
    }

    @NotNull
    public final Function3<View, DslTabBadge, Integer, TabBadgeConfig> getOnTabBadgeConfig() {
        return this.f8775u;
    }

    /* renamed from: getOrientation, reason: from getter */
    public final int getF8780z() {
        return this.f8780z;
    }

    /* renamed from: getScrollAnimDuration, reason: from getter */
    public final int getF8744B() {
        return this.f8744B;
    }

    @Nullable
    /* renamed from: getTabBadge, reason: from getter */
    public final DslTabBadge getF8772r() {
        return this.f8772r;
    }

    @NotNull
    public final Map<Integer, TabBadgeConfig> getTabBadgeConfigMap() {
        return this.f8774t;
    }

    @Nullable
    /* renamed from: getTabBorder, reason: from getter */
    public final DslTabBorder getF8768n() {
        return this.f8768n;
    }

    @Nullable
    /* renamed from: getTabConvexBackgroundDrawable, reason: from getter */
    public final Drawable getF8778x() {
        return this.f8778x;
    }

    /* renamed from: getTabDefaultIndex, reason: from getter */
    public final int getF8766l() {
        return this.f8766l;
    }

    @Nullable
    /* renamed from: getTabDivider, reason: from getter */
    public final DslTabDivider getF8770p() {
        return this.f8770p;
    }

    /* renamed from: getTabEnableSelectorMode, reason: from getter */
    public final boolean getF8779y() {
        return this.f8779y;
    }

    @Nullable
    /* renamed from: getTabHighlight, reason: from getter */
    public final DslTabHighlight getF8777w() {
        return this.f8777w;
    }

    @NotNull
    /* renamed from: getTabIndicator, reason: from getter */
    public final DslTabIndicator getF8764j() {
        return this.f8764j;
    }

    /* renamed from: getTabIndicatorAnimationDuration, reason: from getter */
    public final long getF8765k() {
        return this.f8765k;
    }

    @Nullable
    /* renamed from: getTabLayoutConfig, reason: from getter */
    public final DslTabLayoutConfig getF8767m() {
        return this.f8767m;
    }

    /* renamed from: get_childAllWidthSum, reason: from getter */
    public final int getF8750H() {
        return this.f8750H;
    }

    @NotNull
    public final GestureDetectorCompat get_gestureDetector() {
        return (GestureDetectorCompat) this.f8754L.getValue();
    }

    /* renamed from: get_layoutDirection, reason: from getter */
    public final int getF8752J() {
        return this.f8752J;
    }

    /* renamed from: get_maxConvexHeight, reason: from getter */
    public final int getF8751I() {
        return this.f8751I;
    }

    /* renamed from: get_maxFlingVelocity, reason: from getter */
    public final int getF8746D() {
        return this.f8746D;
    }

    /* renamed from: get_minFlingVelocity, reason: from getter */
    public final int getF8745C() {
        return this.f8745C;
    }

    @NotNull
    public final OverScroller get_overScroller() {
        return (OverScroller) this.f8753K.getValue();
    }

    @NotNull
    public final ValueAnimator get_scrollAnimator() {
        return (ValueAnimator) this.f8755M.getValue();
    }

    @NotNull
    /* renamed from: get_tempRect, reason: from getter */
    public final Rect getF8748F() {
        return this.f8748F;
    }

    /* renamed from: get_touchSlop, reason: from getter */
    public final int getF8747E() {
        return this.f8747E;
    }

    @Nullable
    /* renamed from: get_viewPagerDelegate, reason: from getter */
    public final ViewPagerDelegate getF8756N() {
        return this.f8756N;
    }

    /* renamed from: get_viewPagerScrollState, reason: from getter */
    public final int getF8757O() {
        return this.f8757O;
    }

    /* renamed from: j */
    public void m3870j(float f2) {
        if (getNeedScroll()) {
            if (!this.f8779y) {
                if (!m3866d()) {
                    m3875p(-((int) f2), 0, getMaxHeight());
                    return;
                } else if (m3867e()) {
                    m3875p(-((int) f2), getMinScrollX(), 0);
                    return;
                } else {
                    m3875p(-((int) f2), 0, getMaxScrollX());
                    return;
                }
            }
            if (m3866d() && m3867e()) {
                if (f2 < 0.0f) {
                    m3862o(this, getDslSelector().f1586h - 1, false, false, 6, null);
                    return;
                } else {
                    if (f2 > 0.0f) {
                        m3862o(this, getDslSelector().f1586h + 1, false, false, 6, null);
                        return;
                    }
                    return;
                }
            }
            if (f2 < 0.0f) {
                m3862o(this, getDslSelector().f1586h + 1, false, false, 6, null);
            } else if (f2 > 0.0f) {
                m3862o(this, getDslSelector().f1586h - 1, false, false, 6, null);
            }
        }
    }

    /* renamed from: k */
    public final void m3871k(int i2, float f2) {
        if (get_scrollAnimator().isStarted()) {
            return;
        }
        ViewPagerDelegate viewPagerDelegate = this.f8756N;
        if (i2 < (viewPagerDelegate == null ? 0 : viewPagerDelegate.mo643b())) {
            if (this.f8757O == 1) {
                DslTabIndicator dslTabIndicator = this.f8764j;
                dslTabIndicator.f1632K = i2 + 1;
                dslTabIndicator.f1633L = i2;
            }
            m3864b(1 - f2);
            return;
        }
        if (this.f8757O == 1) {
            DslTabIndicator dslTabIndicator2 = this.f8764j;
            dslTabIndicator2.f1632K = i2;
            dslTabIndicator2.f1633L = i2 + 1;
        }
        m3864b(f2);
    }

    /* renamed from: l */
    public boolean m3872l(float f2) {
        if (!getNeedScroll()) {
            return false;
        }
        getParent().requestDisallowInterceptTouchEvent(true);
        if (!this.f8779y) {
            if (m3866d()) {
                scrollBy((int) f2, 0);
            } else {
                scrollBy(0, (int) f2);
            }
        }
        return true;
    }

    /* renamed from: m */
    public final void m3873m() {
        if (this.f8760f || !getNeedScroll()) {
            if (getScrollX() == 0 && getScrollY() == 0) {
                return;
            }
            scrollTo(0, 0);
        }
    }

    /* renamed from: n */
    public final void m3874n(int i2, boolean z, boolean z2) {
        if (getCurrentItemIndex() == i2) {
            m3865c(i2, this.f8764j.f1630I);
        } else {
            getDslSelector().m662d(i2, (r13 & 2) != 0 ? true : true, (r13 & 4) != 0 ? true : z, (r13 & 8) != 0 ? false : z2, (r13 & 16) != 0 ? false : false);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
    }

    @Override // android.view.View
    public void onDraw(@NotNull Canvas canvas) {
        DslTabBorder dslTabBorder;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        super.onDraw(canvas);
        if (this.f8769o && (dslTabBorder = this.f8768n) != null) {
            dslTabBorder.m667l(canvas);
        }
        if (this.f8763i) {
            DslTabIndicator dslTabIndicator = this.f8764j;
            if (dslTabIndicator.f1635s < 4096) {
                dslTabIndicator.draw(canvas);
            }
        }
    }

    @Override // android.view.View
    public void onFinishInflate() {
        super.onFinishInflate();
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(@NotNull MotionEvent ev) {
        Intrinsics.checkNotNullParameter(ev, "ev");
        if (!getNeedScroll()) {
            return super.onInterceptTouchEvent(ev);
        }
        if (ev.getActionMasked() == 0) {
            get_overScroller().abortAnimation();
            get_scrollAnimator().cancel();
        }
        return super.onInterceptTouchEvent(ev) || get_gestureDetector().onTouchEvent(ev);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean changed, int l2, int t, int r, int b2) {
        if (m3866d()) {
            m3868f();
        } else {
            m3869g();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:120:0x02cb  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x02e3  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x02e4 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:223:0x04e5  */
    /* JADX WARN: Removed duplicated region for block: B:230:0x04fe  */
    /* JADX WARN: Removed duplicated region for block: B:233:0x0500 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:260:0x055e  */
    /* JADX WARN: Removed duplicated region for block: B:265:0x0576  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x0578 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:298:0x0677  */
    /* JADX WARN: Removed duplicated region for block: B:305:0x0690  */
    /* JADX WARN: Removed duplicated region for block: B:308:0x0692 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0113  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x012b  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x012c A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:79:0x018d  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x01a8 A[SYNTHETIC] */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onMeasure(int r33, int r34) {
        /*
            Method dump skipped, instructions count: 1949
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.angcyo.tablayout.DslTabLayout.onMeasure(int, int):void");
    }

    @Override // android.view.View
    public void onRestoreInstanceState(@Nullable Parcelable state) {
        if (!(state instanceof Bundle)) {
            super.onRestoreInstanceState(state);
            return;
        }
        Bundle bundle = (Bundle) state;
        super.onRestoreInstanceState(bundle.getParcelable("old"));
        this.f8766l = bundle.getInt("defaultIndex", this.f8766l);
        int i2 = bundle.getInt("currentIndex", -1);
        getDslSelector().f1586h = -1;
        if (i2 > 0) {
            m3874n(i2, true, false);
        }
    }

    @Override // android.view.View
    public void onRtlPropertiesChanged(int layoutDirection) {
        super.onRtlPropertiesChanged(layoutDirection);
        if (layoutDirection != this.f8752J) {
            this.f8752J = layoutDirection;
            if (this.f8780z == 0) {
                requestLayout();
            }
        }
    }

    @Override // android.view.View
    @Nullable
    public Parcelable onSaveInstanceState() {
        Parcelable onSaveInstanceState = super.onSaveInstanceState();
        Bundle bundle = new Bundle();
        bundle.putParcelable("old", onSaveInstanceState);
        bundle.putInt("defaultIndex", this.f8766l);
        bundle.putInt("currentIndex", getCurrentItemIndex());
        return bundle;
    }

    @Override // android.view.View
    public void onSizeChanged(int w, int h2, int oldw, int oldh) {
        super.onSizeChanged(w, h2, oldw, oldh);
        m3873m();
        if (getDslSelector().f1586h < 0) {
            m3862o(this, this.f8766l, false, false, 6, null);
        } else if (get_overScroller().isFinished()) {
            m3865c(getDslSelector().f1586h, this.f8743A);
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(@NotNull MotionEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (!getNeedScroll()) {
            return super.onTouchEvent(event);
        }
        get_gestureDetector().onTouchEvent(event);
        if (event.getActionMasked() == 3 || event.getActionMasked() == 1) {
            getParent().requestDisallowInterceptTouchEvent(false);
        } else if (event.getActionMasked() == 0) {
            get_overScroller().abortAnimation();
        }
        return true;
    }

    @Override // android.view.ViewGroup
    public void onViewAdded(@Nullable View child) {
        super.onViewAdded(child);
        getDslSelector().m666i();
        getDslSelector().m665h();
        getDslSelector().m664g();
    }

    @Override // android.view.ViewGroup
    public void onViewRemoved(@Nullable View child) {
        super.onViewRemoved(child);
        getDslSelector().m666i();
        getDslSelector().m665h();
        getDslSelector().m664g();
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x000a, code lost:
    
        if (r12 > r1) goto L7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x000c, code lost:
    
        r12 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0017, code lost:
    
        if (r12 > r1) goto L7;
     */
    /* renamed from: p */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m3875p(int r12, int r13, int r14) {
        /*
            r11 = this;
            if (r12 <= 0) goto Le
            int r0 = r11.f8745C
            int r1 = r11.f8746D
            if (r12 >= r0) goto La
        L8:
            r12 = r0
            goto L1a
        La:
            if (r12 <= r1) goto L1a
        Lc:
            r12 = r1
            goto L1a
        Le:
            int r0 = r11.f8746D
            int r0 = -r0
            int r1 = r11.f8745C
            int r1 = -r1
            if (r12 >= r0) goto L17
            goto L8
        L17:
            if (r12 <= r1) goto L1a
            goto Lc
        L1a:
            r4 = r12
            android.widget.OverScroller r12 = r11.get_overScroller()
            r12.abortAnimation()
            boolean r12 = r11.m3866d()
            if (r12 == 0) goto L44
            android.widget.OverScroller r0 = r11.get_overScroller()
            int r1 = r11.getScrollX()
            int r2 = r11.getScrollY()
            r12 = 0
            r7 = 0
            r8 = 0
            int r9 = r11.getMeasuredWidth()
            r10 = 0
            r3 = r4
            r4 = r12
            r5 = r13
            r6 = r14
            r0.fling(r1, r2, r3, r4, r5, r6, r7, r8, r9, r10)
            goto L5d
        L44:
            android.widget.OverScroller r0 = r11.get_overScroller()
            int r1 = r11.getScrollX()
            int r2 = r11.getScrollY()
            r3 = 0
            r5 = 0
            r6 = 0
            r9 = 0
            int r10 = r11.getMeasuredHeight()
            r7 = r13
            r8 = r14
            r0.fling(r1, r2, r3, r4, r5, r6, r7, r8, r9, r10)
        L5d:
            r11.postInvalidate()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.angcyo.tablayout.DslTabLayout.m3875p(int, int, int):void");
    }

    /* renamed from: q */
    public final void m3876q(int i2) {
        get_overScroller().abortAnimation();
        if (m3866d()) {
            get_overScroller().startScroll(getScrollX(), getScrollY(), i2, 0, this.f8744B);
        } else {
            get_overScroller().startScroll(getScrollX(), getScrollY(), 0, i2, this.f8744B);
        }
        ViewCompat.postInvalidateOnAnimation(this);
    }

    @Override // android.view.View
    public void scrollTo(int x, int y) {
        if (m3866d()) {
            if (x > getMaxScrollX()) {
                super.scrollTo(getMaxScrollX(), 0);
                return;
            } else if (x < getMinScrollX()) {
                super.scrollTo(getMinScrollX(), 0);
                return;
            } else {
                super.scrollTo(x, 0);
                return;
            }
        }
        if (y > getMaxScrollY()) {
            super.scrollTo(0, getMaxScrollY());
        } else if (y < getMinScrollY()) {
            super.scrollTo(0, getMinScrollY());
        } else {
            super.scrollTo(0, y);
        }
    }

    public final void setDrawBadge(boolean z) {
        this.f8773s = z;
    }

    public final void setDrawBorder(boolean z) {
        this.f8769o = z;
    }

    public final void setDrawDivider(boolean z) {
        this.f8771q = z;
    }

    public final void setDrawHighlight(boolean z) {
        this.f8776v = z;
    }

    public final void setDrawIndicator(boolean z) {
        this.f8763i = z;
    }

    public final void setItemAutoEquWidth(boolean z) {
        this.f8761g = z;
    }

    public final void setItemDefaultHeight(int i2) {
        this.f8759e = i2;
    }

    public final void setItemIsEquWidth(boolean z) {
        this.f8760f = z;
    }

    public final void setItemWidth(int i2) {
        this.f8762h = i2;
    }

    public final void setLayoutScrollAnim(boolean z) {
        this.f8743A = z;
    }

    public final void setOnTabBadgeConfig(@NotNull Function3<? super View, ? super DslTabBadge, ? super Integer, TabBadgeConfig> function3) {
        Intrinsics.checkNotNullParameter(function3, "<set-?>");
        this.f8775u = function3;
    }

    public final void setOrientation(int i2) {
        this.f8780z = i2;
    }

    public final void setScrollAnimDuration(int i2) {
        this.f8744B = i2;
    }

    public final void setTabBadge(@Nullable DslTabBadge dslTabBadge) {
        this.f8772r = dslTabBadge;
        if (dslTabBadge != null) {
            dslTabBadge.setCallback(this);
        }
        DslTabBadge dslTabBadge2 = this.f8772r;
        if (dslTabBadge2 == null) {
            return;
        }
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        AttributeSet attributeSet = this.f8758c;
        Intrinsics.checkNotNullParameter(context, "context");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.DslTabLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr…R.styleable.DslTabLayout)");
        int color = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_badge_solid_color, dslTabBadge2.f1595H.f1684c);
        dslTabBadge2.f1554c = color;
        TabBadgeConfig tabBadgeConfig = dslTabBadge2.f1595H;
        tabBadgeConfig.f1684c = color;
        int color2 = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_badge_text_color, tabBadgeConfig.f1687f);
        dslTabBadge2.f1538s = color2;
        TabBadgeConfig tabBadgeConfig2 = dslTabBadge2.f1595H;
        tabBadgeConfig2.f1687f = color2;
        int color3 = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_badge_stroke_color, tabBadgeConfig2.f1685d);
        dslTabBadge2.f1555d = color3;
        TabBadgeConfig tabBadgeConfig3 = dslTabBadge2.f1595H;
        tabBadgeConfig3.f1685d = color3;
        int dimensionPixelOffset = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_stroke_width, tabBadgeConfig3.f1686e);
        dslTabBadge2.f1556e = dimensionPixelOffset;
        TabBadgeConfig tabBadgeConfig4 = dslTabBadge2.f1595H;
        tabBadgeConfig4.f1686e = dimensionPixelOffset;
        int i2 = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_badge_gravity, tabBadgeConfig4.f1683b);
        dslTabBadge2.f1537r = i2;
        TabBadgeConfig tabBadgeConfig5 = dslTabBadge2.f1595H;
        tabBadgeConfig5.f1683b = i2;
        int dimensionPixelOffset2 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_offset_x, tabBadgeConfig5.f1691j);
        dslTabBadge2.f1545z = dimensionPixelOffset2;
        TabBadgeConfig tabBadgeConfig6 = dslTabBadge2.f1595H;
        tabBadgeConfig6.f1691j = dimensionPixelOffset2;
        int dimensionPixelOffset3 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_offset_y, tabBadgeConfig6.f1692k);
        dslTabBadge2.f1529A = dimensionPixelOffset3;
        TabBadgeConfig tabBadgeConfig7 = dslTabBadge2.f1595H;
        tabBadgeConfig7.f1692k = dimensionPixelOffset3;
        int dimensionPixelOffset4 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_circle_offset_x, tabBadgeConfig7.f1691j);
        dslTabBadge2.f1543x = dimensionPixelOffset4;
        TabBadgeConfig tabBadgeConfig8 = dslTabBadge2.f1595H;
        tabBadgeConfig8.f1693l = dimensionPixelOffset4;
        int dimensionPixelOffset5 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_circle_offset_y, tabBadgeConfig8.f1692k);
        dslTabBadge2.f1544y = dimensionPixelOffset5;
        TabBadgeConfig tabBadgeConfig9 = dslTabBadge2.f1595H;
        tabBadgeConfig9.f1694m = dimensionPixelOffset5;
        int dimensionPixelOffset6 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_circle_radius, tabBadgeConfig9.f1689h);
        dslTabBadge2.f1542w = dimensionPixelOffset6;
        TabBadgeConfig tabBadgeConfig10 = dslTabBadge2.f1595H;
        tabBadgeConfig10.f1689h = dimensionPixelOffset6;
        int dimensionPixelOffset7 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_radius, tabBadgeConfig10.f1690i);
        Arrays.fill(dslTabBadge2.f1559h, dimensionPixelOffset7);
        TabBadgeConfig tabBadgeConfig11 = dslTabBadge2.f1595H;
        tabBadgeConfig11.f1690i = dimensionPixelOffset7;
        int dimensionPixelOffset8 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_padding_left, tabBadgeConfig11.f1695n);
        dslTabBadge2.f1530B = dimensionPixelOffset8;
        TabBadgeConfig tabBadgeConfig12 = dslTabBadge2.f1595H;
        tabBadgeConfig12.f1695n = dimensionPixelOffset8;
        int dimensionPixelOffset9 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_padding_right, tabBadgeConfig12.f1696o);
        dslTabBadge2.f1531C = dimensionPixelOffset9;
        TabBadgeConfig tabBadgeConfig13 = dslTabBadge2.f1595H;
        tabBadgeConfig13.f1696o = dimensionPixelOffset9;
        int dimensionPixelOffset10 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_padding_top, tabBadgeConfig13.f1697p);
        dslTabBadge2.f1532D = dimensionPixelOffset10;
        TabBadgeConfig tabBadgeConfig14 = dslTabBadge2.f1595H;
        tabBadgeConfig14.f1697p = dimensionPixelOffset10;
        int dimensionPixelOffset11 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_padding_bottom, tabBadgeConfig14.f1698q);
        dslTabBadge2.f1533E = dimensionPixelOffset11;
        dslTabBadge2.f1595H.f1698q = dimensionPixelOffset11;
        dslTabBadge2.f1596I = obtainStyledAttributes.getString(R$styleable.DslTabLayout_tab_badge_text);
        dslTabBadge2.f1540u = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_badge_text_size, (int) dslTabBadge2.f1595H.f1688g);
        dslTabBadge2.m649f().setTextSize(dslTabBadge2.f1540u);
        TabBadgeConfig tabBadgeConfig15 = dslTabBadge2.f1595H;
        tabBadgeConfig15.f1688g = dslTabBadge2.f1540u;
        tabBadgeConfig15.f1699r = obtainStyledAttributes.getInteger(R$styleable.DslTabLayout_tab_badge_anchor_child_index, tabBadgeConfig15.f1699r);
        TabBadgeConfig tabBadgeConfig16 = dslTabBadge2.f1595H;
        tabBadgeConfig16.f1700s = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_badge_ignore_child_padding, tabBadgeConfig16.f1700s);
        TabBadgeConfig tabBadgeConfig17 = dslTabBadge2.f1595H;
        tabBadgeConfig17.f1702u = obtainStyledAttributes.getLayoutDimension(R$styleable.DslTabLayout_tab_badge_min_width, tabBadgeConfig17.f1702u);
        TabBadgeConfig tabBadgeConfig18 = dslTabBadge2.f1595H;
        tabBadgeConfig18.f1701t = obtainStyledAttributes.getLayoutDimension(R$styleable.DslTabLayout_tab_badge_min_height, tabBadgeConfig18.f1701t);
        obtainStyledAttributes.recycle();
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        dslTabBadge2.mo657k();
    }

    public final void setTabBorder(@Nullable DslTabBorder dslTabBorder) {
        this.f8768n = dslTabBorder;
        if (dslTabBorder != null) {
            dslTabBorder.setCallback(this);
        }
        DslTabBorder dslTabBorder2 = this.f8768n;
        if (dslTabBorder2 == null) {
            return;
        }
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        AttributeSet attributeSet = this.f8758c;
        Intrinsics.checkNotNullParameter(context, "context");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.DslTabLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr…R.styleable.DslTabLayout)");
        int color = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_border_solid_color, dslTabBorder2.f1554c);
        dslTabBorder2.f1555d = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_border_stroke_color, dslTabBorder2.f1555d);
        dslTabBorder2.f1556e = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_border_stroke_width, C4195m.m4801d0() * 2);
        Arrays.fill(dslTabBorder2.f1559h, obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_border_radius_size, 0));
        dslTabBorder2.f1565n = obtainStyledAttributes.getDrawable(R$styleable.DslTabLayout_tab_border_drawable);
        dslTabBorder2.f1603q = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_border_draw_item_background, dslTabBorder2.f1603q);
        dslTabBorder2.f1605s = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_border_item_background_width_offset, dslTabBorder2.f1605s);
        dslTabBorder2.f1606t = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_border_item_background_height_offset, dslTabBorder2.f1606t);
        obtainStyledAttributes.recycle();
        if (dslTabBorder2.f1565n == null) {
            DslGradientDrawable dslGradientDrawable = new DslGradientDrawable();
            C1514k config = new C1514k(color, dslTabBorder2);
            Intrinsics.checkNotNullParameter(config, "config");
            config.invoke(dslGradientDrawable);
            dslGradientDrawable.mo657k();
            dslTabBorder2.f1604r = dslGradientDrawable.f1565n;
            dslTabBorder2.mo657k();
        }
    }

    public final void setTabConvexBackgroundDrawable(@Nullable Drawable drawable) {
        this.f8778x = drawable;
    }

    public final void setTabDefaultIndex(int i2) {
        this.f8766l = i2;
    }

    public final void setTabDivider(@Nullable DslTabDivider dslTabDivider) {
        this.f8770p = dslTabDivider;
        if (dslTabDivider != null) {
            dslTabDivider.setCallback(this);
        }
        DslTabDivider dslTabDivider2 = this.f8770p;
        if (dslTabDivider2 == null) {
            return;
        }
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        AttributeSet attributeSet = this.f8758c;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.DslTabLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr…R.styleable.DslTabLayout)");
        dslTabDivider2.f1608q = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_divider_width, dslTabDivider2.f1608q);
        dslTabDivider2.f1609r = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_divider_height, dslTabDivider2.f1609r);
        dslTabDivider2.f1610s = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_divider_margin_left, dslTabDivider2.f1610s);
        dslTabDivider2.f1611t = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_divider_margin_right, dslTabDivider2.f1611t);
        dslTabDivider2.f1612u = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_divider_margin_top, dslTabDivider2.f1612u);
        dslTabDivider2.f1613v = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_divider_margin_bottom, dslTabDivider2.f1613v);
        dslTabDivider2.f1554c = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_divider_solid_color, dslTabDivider2.f1554c);
        dslTabDivider2.f1555d = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_divider_stroke_color, dslTabDivider2.f1555d);
        dslTabDivider2.f1556e = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_divider_stroke_width, 0);
        Arrays.fill(dslTabDivider2.f1559h, obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_divider_radius_size, C4195m.m4801d0() * 2));
        dslTabDivider2.f1565n = obtainStyledAttributes.getDrawable(R$styleable.DslTabLayout_tab_divider_drawable);
        dslTabDivider2.f1614w = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_divider_show_mode, dslTabDivider2.f1614w);
        obtainStyledAttributes.recycle();
        if (dslTabDivider2.f1565n == null) {
            dslTabDivider2.mo657k();
        }
    }

    public final void setTabEnableSelectorMode(boolean z) {
        this.f8779y = z;
    }

    public final void setTabHighlight(@Nullable DslTabHighlight dslTabHighlight) {
        this.f8777w = dslTabHighlight;
        if (dslTabHighlight != null) {
            dslTabHighlight.setCallback(this);
        }
        DslTabHighlight dslTabHighlight2 = this.f8777w;
        if (dslTabHighlight2 == null) {
            return;
        }
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        AttributeSet attributeSet = this.f8758c;
        Intrinsics.checkNotNullParameter(context, "context");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.DslTabLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr…R.styleable.DslTabLayout)");
        dslTabHighlight2.f1616r = obtainStyledAttributes.getDrawable(R$styleable.DslTabLayout_tab_highlight_drawable);
        dslTabHighlight2.f1617s = obtainStyledAttributes.getLayoutDimension(R$styleable.DslTabLayout_tab_highlight_width, dslTabHighlight2.f1617s);
        dslTabHighlight2.f1618t = obtainStyledAttributes.getLayoutDimension(R$styleable.DslTabLayout_tab_highlight_height, dslTabHighlight2.f1618t);
        dslTabHighlight2.f1619u = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_highlight_width_offset, dslTabHighlight2.f1619u);
        dslTabHighlight2.f1620v = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_highlight_height_offset, dslTabHighlight2.f1620v);
        obtainStyledAttributes.recycle();
        if (dslTabHighlight2.f1616r == null && dslTabHighlight2.m655i()) {
            dslTabHighlight2.mo657k();
        }
    }

    public final void setTabIndicator(@NotNull DslTabIndicator value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.f8764j = value;
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        value.m680u(context, this.f8758c);
    }

    public final void setTabIndicatorAnimationDuration(long j2) {
        this.f8765k = j2;
    }

    public final void setTabLayoutConfig(@Nullable DslTabLayoutConfig dslTabLayoutConfig) {
        this.f8767m = dslTabLayoutConfig;
        if (dslTabLayoutConfig == null) {
            return;
        }
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        AttributeSet attributeSet = this.f8758c;
        Intrinsics.checkNotNullParameter(context, "context");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.DslTabLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr…R.styleable.DslTabLayout)");
        dslTabLayoutConfig.f1659i = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_select_color, dslTabLayoutConfig.f1659i);
        dslTabLayoutConfig.f1660j = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_deselect_color, dslTabLayoutConfig.f1660j);
        dslTabLayoutConfig.f1664n = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_ico_select_color, -2);
        dslTabLayoutConfig.f1665o = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_ico_deselect_color, -2);
        boolean z = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_text_color, dslTabLayoutConfig.f1656f);
        dslTabLayoutConfig.f1656f = z;
        if (z) {
            dslTabLayoutConfig.f1662l = true;
        }
        dslTabLayoutConfig.f1658h = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_indicator_gradient_color, dslTabLayoutConfig.f1658h);
        boolean z2 = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_gradient_color, dslTabLayoutConfig.f1657g);
        dslTabLayoutConfig.f1657g = z2;
        if (z2) {
            dslTabLayoutConfig.f1663m = true;
        }
        dslTabLayoutConfig.f1662l = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_ico_color, dslTabLayoutConfig.f1662l);
        dslTabLayoutConfig.f1663m = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_ico_gradient_color, dslTabLayoutConfig.f1663m);
        dslTabLayoutConfig.f1661k = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_text_bold, dslTabLayoutConfig.f1661k);
        dslTabLayoutConfig.f1666p = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_gradient_scale, dslTabLayoutConfig.f1666p);
        dslTabLayoutConfig.f1667q = obtainStyledAttributes.getFloat(R$styleable.DslTabLayout_tab_min_scale, dslTabLayoutConfig.f1667q);
        dslTabLayoutConfig.f1668r = obtainStyledAttributes.getFloat(R$styleable.DslTabLayout_tab_max_scale, dslTabLayoutConfig.f1668r);
        dslTabLayoutConfig.f1669s = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_enable_gradient_text_size, dslTabLayoutConfig.f1669s);
        if (obtainStyledAttributes.hasValue(R$styleable.DslTabLayout_tab_text_min_size)) {
            dslTabLayoutConfig.f1670t = obtainStyledAttributes.getDimensionPixelOffset(r1, (int) dslTabLayoutConfig.f1670t);
        }
        if (obtainStyledAttributes.hasValue(R$styleable.DslTabLayout_tab_text_max_size)) {
            dslTabLayoutConfig.f1671u = obtainStyledAttributes.getDimensionPixelOffset(r1, (int) dslTabLayoutConfig.f1671u);
        }
        dslTabLayoutConfig.f1673w = obtainStyledAttributes.getResourceId(R$styleable.DslTabLayout_tab_text_view_id, dslTabLayoutConfig.f1673w);
        dslTabLayoutConfig.f1674x = obtainStyledAttributes.getResourceId(R$styleable.DslTabLayout_tab_icon_view_id, dslTabLayoutConfig.f1674x);
        obtainStyledAttributes.recycle();
    }

    public final void set_childAllWidthSum(int i2) {
        this.f8750H = i2;
    }

    public final void set_layoutDirection(int i2) {
        this.f8752J = i2;
    }

    public final void set_maxConvexHeight(int i2) {
        this.f8751I = i2;
    }

    public final void set_maxFlingVelocity(int i2) {
        this.f8746D = i2;
    }

    public final void set_minFlingVelocity(int i2) {
        this.f8745C = i2;
    }

    public final void set_touchSlop(int i2) {
        this.f8747E = i2;
    }

    public final void set_viewPagerDelegate(@Nullable ViewPagerDelegate viewPagerDelegate) {
        this.f8756N = viewPagerDelegate;
    }

    public final void set_viewPagerScrollState(int i2) {
        this.f8757O = i2;
    }

    public final void setupViewPager(@NotNull ViewPagerDelegate viewPagerDelegate) {
        Intrinsics.checkNotNullParameter(viewPagerDelegate, "viewPagerDelegate");
        this.f8756N = viewPagerDelegate;
    }

    @Override // android.view.View
    public boolean verifyDrawable(@NotNull Drawable who) {
        Intrinsics.checkNotNullParameter(who, "who");
        return super.verifyDrawable(who) || Intrinsics.areEqual(who, this.f8764j);
    }

    @Override // android.view.ViewGroup
    @NotNull
    public ViewGroup.LayoutParams generateLayoutParams(@Nullable ViewGroup.LayoutParams p) {
        C3200a c3200a = p == null ? null : new C3200a(p);
        return c3200a == null ? generateDefaultLayoutParams() : c3200a;
    }

    @Metadata(m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0010\u0007\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0019\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005¢\u0006\u0002\u0010\u0006B\u000f\b\u0016\u0012\u0006\u0010\u0007\u001a\u00020\b¢\u0006\u0002\u0010\tB\u0017\b\u0016\u0012\u0006\u0010\n\u001a\u00020\u000b\u0012\u0006\u0010\f\u001a\u00020\u000b¢\u0006\u0002\u0010\rB\u001f\b\u0016\u0012\u0006\u0010\n\u001a\u00020\u000b\u0012\u0006\u0010\f\u001a\u00020\u000b\u0012\u0006\u0010\u000e\u001a\u00020\u000b¢\u0006\u0002\u0010\u000fR\u001c\u0010\u0010\u001a\u0004\u0018\u00010\u0011X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0012\u0010\u0013\"\u0004\b\u0014\u0010\u0015R\u001a\u0010\u0016\u001a\u00020\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0017\u0010\u0018\"\u0004\b\u0019\u0010\u001aR\u001a\u0010\u001b\u001a\u00020\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001c\u0010\u0018\"\u0004\b\u001d\u0010\u001aR\u001a\u0010\u001e\u001a\u00020\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001f\u0010\u0018\"\u0004\b \u0010\u001aR\u001c\u0010!\u001a\u0004\u0018\u00010\"X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b#\u0010$\"\u0004\b%\u0010&R\u001c\u0010'\u001a\u0004\u0018\u00010\"X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b(\u0010$\"\u0004\b)\u0010&R\u001a\u0010*\u001a\u00020+X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b,\u0010-\"\u0004\b.\u0010/¨\u00060"}, m5311d2 = {"Lcom/angcyo/tablayout/DslTabLayout$LayoutParams;", "Landroid/widget/FrameLayout$LayoutParams;", "c", "Landroid/content/Context;", "attrs", "Landroid/util/AttributeSet;", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "source", "Landroid/view/ViewGroup$LayoutParams;", "(Landroid/view/ViewGroup$LayoutParams;)V", "width", "", "height", "(II)V", "gravity", "(III)V", "highlightDrawable", "Landroid/graphics/drawable/Drawable;", "getHighlightDrawable", "()Landroid/graphics/drawable/Drawable;", "setHighlightDrawable", "(Landroid/graphics/drawable/Drawable;)V", "indicatorContentId", "getIndicatorContentId", "()I", "setIndicatorContentId", "(I)V", "indicatorContentIndex", "getIndicatorContentIndex", "setIndicatorContentIndex", "layoutConvexHeight", "getLayoutConvexHeight", "setLayoutConvexHeight", "layoutHeight", "", "getLayoutHeight", "()Ljava/lang/String;", "setLayoutHeight", "(Ljava/lang/String;)V", "layoutWidth", "getLayoutWidth", "setLayoutWidth", ActivityChooserModel.ATTRIBUTE_WEIGHT, "", "getWeight", "()F", "setWeight", "(F)V", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.angcyo.tablayout.DslTabLayout$a */
    public static final class C3200a extends FrameLayout.LayoutParams {

        /* renamed from: a */
        @Nullable
        public String f8781a;

        /* renamed from: b */
        @Nullable
        public String f8782b;

        /* renamed from: c */
        public int f8783c;

        /* renamed from: d */
        public int f8784d;

        /* renamed from: e */
        public int f8785e;

        /* renamed from: f */
        public float f8786f;

        /* renamed from: g */
        @Nullable
        public Drawable f8787g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3200a(@NotNull Context c2, @Nullable AttributeSet attributeSet) {
            super(c2, attributeSet);
            Intrinsics.checkNotNullParameter(c2, "c");
            this.f8784d = -1;
            this.f8785e = -1;
            this.f8786f = -1.0f;
            TypedArray obtainStyledAttributes = c2.obtainStyledAttributes(attributeSet, R$styleable.DslTabLayout_Layout);
            Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "c.obtainStyledAttributes…able.DslTabLayout_Layout)");
            this.f8781a = obtainStyledAttributes.getString(R$styleable.DslTabLayout_Layout_layout_tab_width);
            this.f8782b = obtainStyledAttributes.getString(R$styleable.DslTabLayout_Layout_layout_tab_height);
            this.f8783c = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_Layout_layout_tab_convex_height, this.f8783c);
            this.f8784d = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_Layout_layout_tab_indicator_content_index, this.f8784d);
            this.f8785e = obtainStyledAttributes.getResourceId(R$styleable.DslTabLayout_Layout_layout_tab_indicator_content_id, this.f8785e);
            this.f8786f = obtainStyledAttributes.getFloat(R$styleable.DslTabLayout_Layout_layout_tab_weight, this.f8786f);
            this.f8787g = obtainStyledAttributes.getDrawable(R$styleable.DslTabLayout_Layout_layout_highlight_drawable);
            obtainStyledAttributes.recycle();
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3200a(@NotNull ViewGroup.LayoutParams source) {
            super(source);
            Intrinsics.checkNotNullParameter(source, "source");
            this.f8784d = -1;
            this.f8785e = -1;
            this.f8786f = -1.0f;
            if (source instanceof C3200a) {
                C3200a c3200a = (C3200a) source;
                this.f8781a = c3200a.f8781a;
                this.f8782b = c3200a.f8782b;
                this.f8783c = c3200a.f8783c;
                this.f8786f = c3200a.f8786f;
                this.f8787g = c3200a.f8787g;
            }
        }

        public C3200a(int i2, int i3, int i4) {
            super(i2, i3, i4);
            this.f8784d = -1;
            this.f8785e = -1;
            this.f8786f = -1.0f;
        }
    }
}

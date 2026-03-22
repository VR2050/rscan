package io.github.armcha.autolink;

import android.content.Context;
import android.text.DynamicLayout;
import android.text.SpannableString;
import android.text.StaticLayout;
import android.text.style.CharacterStyle;
import android.util.AttributeSet;
import android.widget.TextView;
import androidx.core.internal.view.SupportMenu;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.collections.CollectionsKt__MutableCollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p310s.p311a.C2743m;
import p429g.p430a.p431a.p432a.AbstractC4331f;
import p429g.p430a.p431a.p432a.C4326a;
import p429g.p430a.p431a.p432a.C4327b;
import p429g.p430a.p431a.p432a.C4328c;
import p429g.p430a.p431a.p432a.C4329d;
import p429g.p430a.p431a.p432a.C4330e;
import p429g.p430a.p431a.p432a.C4332g;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000r\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\r\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u000b\n\u0002\u0010#\n\u0002\b\u0005\n\u0002\u0010%\n\u0002\u0010\u000e\n\u0002\b\u0013\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u001b\u0012\u0006\u0010L\u001a\u00020K\u0012\n\b\u0002\u0010N\u001a\u0004\u0018\u00010M¢\u0006\u0004\bO\u0010PJ\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ!\u0010\f\u001a\u00020\u00062\u0012\u0010\u000b\u001a\n\u0012\u0006\b\u0001\u0012\u00020\n0\t\"\u00020\n¢\u0006\u0004\b\f\u0010\rJ)\u0010\u0011\u001a\u00020\u00062\u0006\u0010\u000e\u001a\u00020\n2\u0012\u0010\u0010\u001a\n\u0012\u0006\b\u0001\u0012\u00020\u000f0\t\"\u00020\u000f¢\u0006\u0004\b\u0011\u0010\u0012J!\u0010\u0016\u001a\u00020\u00062\u0012\u0010\u0015\u001a\u000e\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u00060\u0013¢\u0006\u0004\b\u0016\u0010\u0017J\u001f\u0010\u001b\u001a\u00020\u00062\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001a\u001a\u00020\u0018H\u0014¢\u0006\u0004\b\u001b\u0010\u001cR\"\u0010#\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001f\u0010 \"\u0004\b!\u0010\"R\u001c\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\n0$8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b%\u0010&R$\u0010)\u001a\u0010\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b'\u0010(R\"\u0010.\u001a\u000e\u0012\u0004\u0012\u00020+\u0012\u0004\u0012\u00020+0*8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b,\u0010-R\"\u00102\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b/\u0010\u001e\u001a\u0004\b0\u0010 \"\u0004\b1\u0010\"R\"\u00106\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b3\u0010\u001e\u001a\u0004\b4\u0010 \"\u0004\b5\u0010\"R\"\u0010:\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b7\u0010\u001e\u001a\u0004\b8\u0010 \"\u0004\b9\u0010\"R\"\u0010>\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b;\u0010\u001e\u001a\u0004\b<\u0010 \"\u0004\b=\u0010\"R2\u0010B\u001a\u001e\u0012\u0004\u0012\u00020\n\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020\u000f0?j\b\u0012\u0004\u0012\u00020\u000f`@0*8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bA\u0010-R\"\u0010F\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bC\u0010\u001e\u001a\u0004\bD\u0010 \"\u0004\bE\u0010\"R\"\u0010J\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bG\u0010\u001e\u001a\u0004\bH\u0010 \"\u0004\bI\u0010\"¨\u0006Q"}, m5311d2 = {"Lio/github/armcha/autolink/AutoLinkTextView;", "Landroid/widget/TextView;", "", "text", "Landroid/widget/TextView$BufferType;", "type", "", "setText", "(Ljava/lang/CharSequence;Landroid/widget/TextView$BufferType;)V", "", "Lg/a/a/a/f;", "modes", "a", "([Lio/github/armcha/autolink/Mode;)V", "mode", "Landroid/text/style/CharacterStyle;", "spans", "b", "(Lg/a/a/a/f;[Landroid/text/style/CharacterStyle;)V", "Lkotlin/Function1;", "Lg/a/a/a/a;", "body", "c", "(Lkotlin/jvm/functions/Function1;)V", "", "widthMeasureSpec", "heightMeasureSpec", "onMeasure", "(II)V", "j", "I", "getMentionModeColor", "()I", "setMentionModeColor", "(I)V", "mentionModeColor", "", "g", "Ljava/util/Set;", "h", "Lkotlin/jvm/functions/Function1;", "onAutoLinkClick", "", "", "f", "Ljava/util/Map;", "transformations", "k", "getHashTagModeColor", "setHashTagModeColor", "hashTagModeColor", C2743m.f7506a, "getPhoneModeColor", "setPhoneModeColor", "phoneModeColor", "o", "getUrlModeColor", "setUrlModeColor", "urlModeColor", "i", "getPressedTextColor", "setPressedTextColor", "pressedTextColor", "Ljava/util/HashSet;", "Lkotlin/collections/HashSet;", C1568e.f1949a, "spanMap", "l", "getCustomModeColor", "setCustomModeColor", "customModeColor", "n", "getEmailModeColor", "setEmailModeColor", "emailModeColor", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "autolinklibrary_release"}, m5312k = 1, m5313mv = {1, 4, 1})
/* loaded from: classes2.dex */
public final class AutoLinkTextView extends TextView {

    /* renamed from: c */
    @NotNull
    public static final String f11281c;

    /* renamed from: e, reason: from kotlin metadata */
    public final Map<AbstractC4331f, HashSet<CharacterStyle>> spanMap;

    /* renamed from: f, reason: from kotlin metadata */
    public final Map<String, String> transformations;

    /* renamed from: g, reason: from kotlin metadata */
    public final Set<AbstractC4331f> modes;

    /* renamed from: h, reason: from kotlin metadata */
    public Function1<? super C4326a, Unit> onAutoLinkClick;

    /* renamed from: i, reason: from kotlin metadata */
    public int pressedTextColor;

    /* renamed from: j, reason: from kotlin metadata */
    public int mentionModeColor;

    /* renamed from: k, reason: from kotlin metadata */
    public int hashTagModeColor;

    /* renamed from: l, reason: from kotlin metadata */
    public int customModeColor;

    /* renamed from: m, reason: from kotlin metadata */
    public int phoneModeColor;

    /* renamed from: n, reason: from kotlin metadata */
    public int emailModeColor;

    /* renamed from: o, reason: from kotlin metadata */
    public int urlModeColor;

    static {
        String simpleName = AutoLinkTextView.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "AutoLinkTextView::class.java.simpleName");
        f11281c = simpleName;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AutoLinkTextView(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        this.spanMap = new LinkedHashMap();
        this.transformations = new LinkedHashMap();
        this.modes = new LinkedHashSet();
        this.pressedTextColor = -3355444;
        this.mentionModeColor = SupportMenu.CATEGORY_MASK;
        this.hashTagModeColor = SupportMenu.CATEGORY_MASK;
        this.customModeColor = SupportMenu.CATEGORY_MASK;
        this.phoneModeColor = SupportMenu.CATEGORY_MASK;
        this.emailModeColor = SupportMenu.CATEGORY_MASK;
        this.urlModeColor = SupportMenu.CATEGORY_MASK;
        setHighlightColor(0);
        setMovementMethod(new C4329d());
    }

    /* renamed from: a */
    public final void m4937a(@NotNull AbstractC4331f... modes) {
        Intrinsics.checkNotNullParameter(modes, "modes");
        CollectionsKt__MutableCollectionsKt.addAll(this.modes, modes);
    }

    /* renamed from: b */
    public final void m4938b(@NotNull AbstractC4331f mode, @NotNull CharacterStyle... spans) {
        Intrinsics.checkNotNullParameter(mode, "mode");
        Intrinsics.checkNotNullParameter(spans, "spans");
        this.spanMap.put(mode, ArraysKt___ArraysKt.toHashSet(spans));
    }

    /* renamed from: c */
    public final void m4939c(@NotNull Function1<? super C4326a, Unit> body) {
        Intrinsics.checkNotNullParameter(body, "body");
        this.onAutoLinkClick = body;
    }

    public final int getCustomModeColor() {
        return this.customModeColor;
    }

    public final int getEmailModeColor() {
        return this.emailModeColor;
    }

    public final int getHashTagModeColor() {
        return this.hashTagModeColor;
    }

    public final int getMentionModeColor() {
        return this.mentionModeColor;
    }

    public final int getPhoneModeColor() {
        return this.phoneModeColor;
    }

    public final int getPressedTextColor() {
        return this.pressedTextColor;
    }

    public final int getUrlModeColor() {
        return this.urlModeColor;
    }

    @Override // android.widget.TextView, android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        Field declaredField = DynamicLayout.class.getDeclaredField("sStaticLayout");
        Intrinsics.checkNotNullExpressionValue(declaredField, "DynamicLayout::class.jav…redField(\"sStaticLayout\")");
        declaredField.setAccessible(true);
        Object obj = declaredField.get(DynamicLayout.class);
        Field field = null;
        if (!(obj instanceof StaticLayout)) {
            obj = null;
        }
        StaticLayout staticLayout = (StaticLayout) obj;
        if (staticLayout != null) {
            field = StaticLayout.class.getDeclaredField("mMaximumVisibleLineCount");
            field.setAccessible(true);
            field.setInt(staticLayout, getMaxLines());
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        if (staticLayout == null || field == null) {
            return;
        }
        field.setInt(staticLayout, Integer.MAX_VALUE);
    }

    public final void setCustomModeColor(int i2) {
        this.customModeColor = i2;
    }

    public final void setEmailModeColor(int i2) {
        this.emailModeColor = i2;
    }

    public final void setHashTagModeColor(int i2) {
        this.hashTagModeColor = i2;
    }

    public final void setMentionModeColor(int i2) {
        this.mentionModeColor = i2;
    }

    public final void setPhoneModeColor(int i2) {
        this.phoneModeColor = i2;
    }

    public final void setPressedTextColor(int i2) {
        this.pressedTextColor = i2;
    }

    @Override // android.widget.TextView
    public void setText(@NotNull CharSequence text, @NotNull TextView.BufferType type) {
        String sb;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(type, "type");
        boolean z = true;
        if (!(text.length() == 0)) {
            Set<AbstractC4331f> set = this.modes;
            if (set != null && !set.isEmpty()) {
                z = false;
            }
            if (!z) {
                ArrayList arrayList = new ArrayList();
                for (AbstractC4331f toPattern : this.modes) {
                    Intrinsics.checkNotNullParameter(toPattern, "$this$toPattern");
                    if (!(toPattern instanceof C4330e)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    String[] strArr = ((C4330e) toPattern).f11180a;
                    ArrayList arrayList2 = new ArrayList(strArr.length);
                    for (String str : strArr) {
                        arrayList2.add(str.length() > 2 ? Pattern.compile(str) : C4332g.f11181a);
                    }
                    Iterator it = arrayList2.iterator();
                    while (it.hasNext()) {
                        Matcher matcher = ((Pattern) it.next()).matcher(text);
                        while (matcher.find()) {
                            String matchedText = matcher.group();
                            int start = matcher.start();
                            int end = matcher.end();
                            Intrinsics.checkNotNullExpressionValue(matchedText, "group");
                            Intrinsics.checkNotNullExpressionValue(matchedText, "matchedText");
                            arrayList.add(new C4326a(start, end, matchedText, matchedText, toPattern));
                        }
                    }
                }
                if (this.transformations.isEmpty()) {
                    sb = text.toString();
                } else {
                    StringBuilder sb2 = new StringBuilder(text);
                    Iterator it2 = CollectionsKt___CollectionsKt.sortedWith(arrayList, new C4328c()).iterator();
                    while (it2.hasNext()) {
                        AbstractC4331f abstractC4331f = ((C4326a) it2.next()).f11176e;
                    }
                    sb = sb2.toString();
                    Intrinsics.checkNotNullExpressionValue(sb, "stringBuilder.toString()");
                }
                SpannableString spannableString = new SpannableString(sb);
                Iterator it3 = arrayList.iterator();
                while (it3.hasNext()) {
                    C4326a c4326a = (C4326a) it3.next();
                    AbstractC4331f abstractC4331f2 = c4326a.f11176e;
                    if (!(abstractC4331f2 instanceof C4330e)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    int i2 = this.customModeColor;
                    spannableString.setSpan(new C4327b(this, c4326a, i2, i2, this.pressedTextColor), c4326a.f11172a, c4326a.f11173b, 33);
                    HashSet<CharacterStyle> hashSet = this.spanMap.get(abstractC4331f2);
                    if (hashSet != null) {
                        Iterator<T> it4 = hashSet.iterator();
                        while (it4.hasNext()) {
                            CharacterStyle wrap = CharacterStyle.wrap((CharacterStyle) it4.next());
                            Intrinsics.checkNotNullExpressionValue(wrap, "CharacterStyle.wrap(it)");
                            spannableString.setSpan(wrap, c4326a.f11172a, c4326a.f11173b, 33);
                        }
                    }
                }
                super.setText(spannableString, type);
                return;
            }
        }
        super.setText(text, type);
    }

    public final void setUrlModeColor(int i2) {
        this.urlModeColor = i2;
    }
}

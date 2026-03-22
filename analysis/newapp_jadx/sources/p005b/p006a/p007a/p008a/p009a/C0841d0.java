package p005b.p006a.p007a.p008a.p009a;

import android.content.SharedPreferences;
import android.text.TextUtils;
import com.alibaba.fastjson.JSON;
import java.util.List;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

/* renamed from: b.a.a.a.a.d0 */
/* loaded from: classes2.dex */
public final class C0841d0 {

    /* renamed from: a */
    @Nullable
    public static List<String> f236a;

    /* renamed from: a */
    public static final boolean m178a(@NotNull String content) {
        boolean z;
        List<String> list;
        Intrinsics.checkNotNullParameter(content, "content");
        if (TextUtils.isEmpty(content)) {
            return false;
        }
        if (f236a == null) {
            m179b();
        }
        List<String> list2 = f236a;
        Boolean valueOf = list2 == null ? null : Boolean.valueOf(list2.contains(content));
        Intrinsics.checkNotNull(valueOf);
        if (valueOf.booleanValue()) {
            List<String> list3 = f236a;
            if (list3 != null) {
                list3.remove(content);
            }
            List<String> list4 = f236a;
            if (list4 != null) {
                list4.add(0, content);
            }
            z = false;
        } else {
            List<String> list5 = f236a;
            if (list5 != null) {
                list5.add(0, content);
            }
            z = true;
        }
        List<String> list6 = f236a;
        Integer valueOf2 = list6 == null ? null : Integer.valueOf(list6.size());
        Intrinsics.checkNotNull(valueOf2);
        if (valueOf2.intValue() > 8 && (list = f236a) != null) {
        }
        String value = JSON.toJSONString(f236a);
        Intrinsics.checkNotNullExpressionValue(value, "toJSONString(historyItems)");
        Intrinsics.checkNotNullParameter("history", "key");
        Intrinsics.checkNotNullParameter(value, "value");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
        editor.putString("history", value);
        editor.commit();
        return z;
    }

    @NotNull
    /* renamed from: b */
    public static final List<String> m179b() {
        if (f236a == null) {
            Intrinsics.checkNotNullParameter("history", "key");
            Intrinsics.checkNotNullParameter("[]", "default");
            ApplicationC2828a applicationC2828a = C2827a.f7670a;
            if (applicationC2828a == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
            Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
            String string = sharedPreferences.getString("history", "[]");
            Intrinsics.checkNotNull(string);
            List parseArray = JSON.parseArray(string, String.class);
            Objects.requireNonNull(parseArray, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.String>");
            f236a = TypeIntrinsics.asMutableList(parseArray);
        }
        List<String> list = f236a;
        Objects.requireNonNull(list, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.String>");
        return TypeIntrinsics.asMutableList(list);
    }
}

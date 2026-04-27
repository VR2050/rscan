package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span;

import android.graphics.Color;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.AtUserSpan, reason: from toString */
/* JADX INFO: compiled from: AtUserSpan.kt */
/* JADX INFO: loaded from: classes5.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\t\n\u0002\b\u0016\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\b\u0018\u00002\u00020\u00012\u00020\u0002B/\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\b\u0010\u0007\u001a\u0004\u0018\u00010\u0006\u0012\u0006\u0010\b\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\n¢\u0006\u0002\u0010\u000bJ\t\u0010\u001a\u001a\u00020\u0004HÆ\u0003J\t\u0010\u001b\u001a\u00020\u0006HÆ\u0003J\u000b\u0010\u001c\u001a\u0004\u0018\u00010\u0006HÆ\u0003J\t\u0010\u001d\u001a\u00020\u0006HÆ\u0003J\t\u0010\u001e\u001a\u00020\nHÆ\u0003J=\u0010\u001f\u001a\u00020\u00002\b\b\u0002\u0010\u0003\u001a\u00020\u00042\b\b\u0002\u0010\u0005\u001a\u00020\u00062\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u00062\b\b\u0002\u0010\b\u001a\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\nHÆ\u0001J\u0013\u0010 \u001a\u00020!2\b\u0010\"\u001a\u0004\u0018\u00010#HÖ\u0003J\u0006\u0010$\u001a\u00020%J\t\u0010&\u001a\u00020\u0004HÖ\u0001J\u0010\u0010'\u001a\u00020!2\u0006\u0010(\u001a\u00020%H\u0016J\b\u0010)\u001a\u00020\u0006H\u0016R\u001a\u0010\t\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR\u001a\u0010\u0005\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0010\u0010\u0011\"\u0004\b\u0012\u0010\u0013R\u001a\u0010\b\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0014\u0010\u0011\"\u0004\b\u0015\u0010\u0013R\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u0017R\u001c\u0010\u0007\u001a\u0004\u0018\u00010\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0018\u0010\u0011\"\u0004\b\u0019\u0010\u0013¨\u0006*"}, d2 = {"Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/span/AtUserSpan;", "Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/span/DataBindingSpan;", "Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/span/DirtySpan;", "userID", "", "nickName", "", "userName", "showName", "accessHash", "", "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V", "getAccessHash", "()J", "setAccessHash", "(J)V", "getNickName", "()Ljava/lang/String;", "setNickName", "(Ljava/lang/String;)V", "getShowName", "setShowName", "getUserID", "()I", "getUserName", "setUserName", "component1", "component2", "component3", "component4", "component5", "copy", "equals", "", "other", "", "getSpannedName", "Landroid/text/Spannable;", "hashCode", "isDirty", "text", "toString", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
public final /* data */ class User implements DataBindingSpan, DirtySpan {
    private long accessHash;
    private String nickName;
    private String showName;
    private final int userID;
    private String userName;

    public static /* synthetic */ User copy$default(User user, int i, String str, String str2, String str3, long j, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            i = user.userID;
        }
        if ((i2 & 2) != 0) {
            str = user.nickName;
        }
        String str4 = str;
        if ((i2 & 4) != 0) {
            str2 = user.userName;
        }
        String str5 = str2;
        if ((i2 & 8) != 0) {
            str3 = user.showName;
        }
        String str6 = str3;
        if ((i2 & 16) != 0) {
            j = user.accessHash;
        }
        return user.copy(i, str4, str5, str6, j);
    }

    /* JADX INFO: renamed from: component1, reason: from getter */
    public final int getUserID() {
        return this.userID;
    }

    /* JADX INFO: renamed from: component2, reason: from getter */
    public final String getNickName() {
        return this.nickName;
    }

    /* JADX INFO: renamed from: component3, reason: from getter */
    public final String getUserName() {
        return this.userName;
    }

    /* JADX INFO: renamed from: component4, reason: from getter */
    public final String getShowName() {
        return this.showName;
    }

    /* JADX INFO: renamed from: component5, reason: from getter */
    public final long getAccessHash() {
        return this.accessHash;
    }

    public final User copy(int userID, String nickName, String userName, String showName, long accessHash) {
        Intrinsics.checkParameterIsNotNull(nickName, "nickName");
        Intrinsics.checkParameterIsNotNull(showName, "showName");
        return new User(userID, nickName, userName, showName, accessHash);
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof User)) {
            return false;
        }
        User user = (User) other;
        return this.userID == user.userID && Intrinsics.areEqual(this.nickName, user.nickName) && Intrinsics.areEqual(this.userName, user.userName) && Intrinsics.areEqual(this.showName, user.showName) && this.accessHash == user.accessHash;
    }

    public int hashCode() {
        int i = this.userID * 31;
        String str = this.nickName;
        int iHashCode = (i + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.userName;
        int iHashCode2 = (iHashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.showName;
        int iHashCode3 = str3 != null ? str3.hashCode() : 0;
        long j = this.accessHash;
        return ((iHashCode2 + iHashCode3) * 31) + ((int) (j ^ (j >>> 32)));
    }

    public User(int userID, String nickName, String userName, String showName, long accessHash) {
        Intrinsics.checkParameterIsNotNull(nickName, "nickName");
        Intrinsics.checkParameterIsNotNull(showName, "showName");
        this.userID = userID;
        this.nickName = nickName;
        this.userName = userName;
        this.showName = showName;
        this.accessHash = accessHash;
    }

    public final long getAccessHash() {
        return this.accessHash;
    }

    public final String getNickName() {
        return this.nickName;
    }

    public final String getShowName() {
        return this.showName;
    }

    public final int getUserID() {
        return this.userID;
    }

    public final String getUserName() {
        return this.userName;
    }

    public final void setAccessHash(long j) {
        this.accessHash = j;
    }

    public final void setNickName(String str) {
        Intrinsics.checkParameterIsNotNull(str, "<set-?>");
        this.nickName = str;
    }

    public final void setShowName(String str) {
        Intrinsics.checkParameterIsNotNull(str, "<set-?>");
        this.showName = str;
    }

    public final void setUserName(String str) {
        this.userName = str;
    }

    public final Spannable getSpannedName() {
        SpannableString $this$apply = new SpannableString(this.showName);
        $this$apply.setSpan(new ForegroundColorSpan(Color.parseColor("#5080B5")), 0, $this$apply.length(), 33);
        return $this$apply;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.DirtySpan
    public boolean isDirty(Spannable text) {
        Intrinsics.checkParameterIsNotNull(text, "text");
        int spanStart = text.getSpanStart(this);
        int spanEnd = text.getSpanEnd(this);
        return spanStart >= 0 && spanEnd >= 0 && (Intrinsics.areEqual(text.subSequence(spanStart, spanEnd).toString(), this.showName) ^ true);
    }

    public String toString() {
        return "User(userID=" + this.userID + ", nickName='" + this.nickName + "', userName='" + this.userName + "', showName='" + this.showName + "', accessHash=" + this.accessHash + ')';
    }
}

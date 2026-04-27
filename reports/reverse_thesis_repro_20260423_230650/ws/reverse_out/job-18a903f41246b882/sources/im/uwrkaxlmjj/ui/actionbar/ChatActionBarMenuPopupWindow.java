package im.uwrkaxlmjj.ui.actionbar;

import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.components.LayoutHelper;

/* JADX INFO: loaded from: classes5.dex */
public class ChatActionBarMenuPopupWindow extends PopupWindow {
    private Context context;
    private FrameLayout frameLayout;
    private LinearLayout llContent;
    private OnSubItemClickListener mOnSubItemClickListener;

    public interface OnSubItemClickListener {
        void onClick(int i);
    }

    public void setOnSubItemClickListener(OnSubItemClickListener listener) {
        this.mOnSubItemClickListener = listener;
    }

    public ChatActionBarMenuPopupWindow(Context context) {
        super(-1, AndroidUtilities.dp(50.0f));
        this.context = context;
        init();
    }

    private void init() {
        LinearLayout linearLayout = new LinearLayout(this.context);
        this.llContent = linearLayout;
        linearLayout.setBackgroundColor(Theme.getColor(Theme.key_actionBarDefault));
        this.llContent.setOrientation(0);
        this.llContent.setGravity(16);
        FrameLayout frameLayout = new FrameLayout(this.context);
        this.frameLayout = frameLayout;
        this.llContent.addView(frameLayout, LayoutHelper.createLinear(0, -1, 1.0f));
        this.frameLayout.setVisibility(8);
        setContentView(this.llContent);
    }

    public ChatActionBarMenuSubItem addSubItem(final int id, int icon, String text) {
        ChatActionBarMenuSubItem chatActionBarMenuSubItem = new ChatActionBarMenuSubItem(this.context);
        chatActionBarMenuSubItem.setTag(Integer.valueOf(id));
        chatActionBarMenuSubItem.setTextAndIcon(text, icon);
        chatActionBarMenuSubItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ChatActionBarMenuPopupWindow$-abxxJqjhhdf2CdAsRLCiauikwg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addSubItem$0$ChatActionBarMenuPopupWindow(id, view);
            }
        });
        this.llContent.addView(chatActionBarMenuSubItem, LayoutHelper.createLinear(0, -1, 1.0f));
        return chatActionBarMenuSubItem;
    }

    public /* synthetic */ void lambda$addSubItem$0$ChatActionBarMenuPopupWindow(int id, View v) {
        OnSubItemClickListener onSubItemClickListener = this.mOnSubItemClickListener;
        if (onSubItemClickListener != null) {
            onSubItemClickListener.onClick(id);
        }
    }

    public ChatActionBarMenuSubItem addLiveSubItem(final int id, int icon, String text) {
        ChatActionBarMenuSubItem chatActionBarMenuSubItem = new ChatActionBarMenuSubItem(this.context);
        chatActionBarMenuSubItem.setTag(Integer.valueOf(id));
        chatActionBarMenuSubItem.setTextAndIcon(text, icon);
        chatActionBarMenuSubItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ChatActionBarMenuPopupWindow$_R26AJR8178vh-4dM1eIcxNu83M
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addLiveSubItem$1$ChatActionBarMenuPopupWindow(id, view);
            }
        });
        this.frameLayout.setVisibility(0);
        this.frameLayout.addView(chatActionBarMenuSubItem, LayoutHelper.createFrame(-1, -1.0f));
        return chatActionBarMenuSubItem;
    }

    public /* synthetic */ void lambda$addLiveSubItem$1$ChatActionBarMenuPopupWindow(int id, View v) {
        OnSubItemClickListener onSubItemClickListener = this.mOnSubItemClickListener;
        if (onSubItemClickListener != null) {
            onSubItemClickListener.onClick(id);
        }
    }

    public void hideLiveSubItem() {
        this.frameLayout.setVisibility(8);
    }

    public void hideSubItem(int id) {
        View view = this.llContent.findViewWithTag(Integer.valueOf(id));
        if (view != null && view.getVisibility() != 8) {
            view.setVisibility(8);
        }
    }

    public int getItemCount() {
        return this.llContent.getChildCount();
    }
}

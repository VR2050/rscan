package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChatUnreadCell extends FrameLayout {
    private TextView textView;

    public ChatUnreadCell(Context context) {
        this(context, null);
    }

    public ChatUnreadCell(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public ChatUnreadCell(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        View view = View.inflate(context, R.layout.item_message_unread_layout, null);
        TextView textView = (TextView) view.findViewById(R.attr.tv_msg_unread_text);
        this.textView = textView;
        textView.setTextSize(1, 14.0f);
        this.textView.setTextColor(Theme.getColor(Theme.key_chat_unreadMessagesStartText));
        addView(view, LayoutHelper.createFrame(-1, 20.0f));
    }

    public void setText(String text) {
        this.textView.setText(text);
    }

    public TextView getTextView() {
        return this.textView;
    }
}

package com.jbzd.media.movecartoons.view.text;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.text.SpannableString;
import android.text.TextPaint;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.util.AttributeSet;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.AppCompatTextView;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public class AutoLinkTextView extends AppCompatTextView {
    private final String regex;

    public static class GoToURLSpan extends ClickableSpan {
        private final String url;

        public GoToURLSpan(@NonNull String str) {
            this.url = str;
        }

        @Override // android.text.style.ClickableSpan
        public void onClick(View view) {
            view.getContext().startActivity(new Intent("android.intent.action.VIEW", Uri.parse(this.url)));
        }

        @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
        public void updateDrawState(@NonNull TextPaint textPaint) {
            super.updateDrawState(textPaint);
            textPaint.setColor(Color.argb(255, 186, 145, 34));
        }
    }

    public AutoLinkTextView(Context context) {
        super(context);
        this.regex = "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    }

    @Override // android.widget.TextView
    public void setText(CharSequence charSequence, TextView.BufferType bufferType) {
        String charSequence2 = charSequence.toString();
        SpannableString spannableString = new SpannableString(charSequence2);
        Matcher matcher = Pattern.compile("(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]").matcher(charSequence2);
        while (matcher.find()) {
            String group = matcher.group();
            spannableString.setSpan(new GoToURLSpan(group), matcher.start(), matcher.end(), 0);
        }
        super.setText(spannableString, bufferType);
        super.setMovementMethod(new LinkMovementMethod());
    }

    public AutoLinkTextView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.regex = "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    }

    public AutoLinkTextView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.regex = "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
    }
}

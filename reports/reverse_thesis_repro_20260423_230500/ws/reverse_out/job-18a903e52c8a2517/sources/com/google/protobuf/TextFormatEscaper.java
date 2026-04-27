package com.google.protobuf;

/* JADX INFO: loaded from: classes.dex */
final class TextFormatEscaper {

    private interface ByteSequence {
        byte byteAt(int i);

        int size();
    }

    private TextFormatEscaper() {
    }

    static String escapeBytes(ByteSequence input) {
        StringBuilder builder = new StringBuilder(input.size());
        for (int i = 0; i < input.size(); i++) {
            byte b = input.byteAt(i);
            if (b == 34) {
                builder.append("\\\"");
            } else if (b == 39) {
                builder.append("\\'");
            } else if (b != 92) {
                switch (b) {
                    case 7:
                        builder.append("\\a");
                        break;
                    case 8:
                        builder.append("\\b");
                        break;
                    case 9:
                        builder.append("\\t");
                        break;
                    case 10:
                        builder.append("\\n");
                        break;
                    case 11:
                        builder.append("\\v");
                        break;
                    case 12:
                        builder.append("\\f");
                        break;
                    case 13:
                        builder.append("\\r");
                        break;
                    default:
                        if (b >= 32 && b <= 126) {
                            builder.append((char) b);
                        } else {
                            builder.append('\\');
                            builder.append((char) (((b >>> 6) & 3) + 48));
                            builder.append((char) (((b >>> 3) & 7) + 48));
                            builder.append((char) ((b & 7) + 48));
                        }
                        break;
                }
            } else {
                builder.append("\\\\");
            }
        }
        return builder.toString();
    }

    static String escapeBytes(final ByteString input) {
        return escapeBytes(new ByteSequence() { // from class: com.google.protobuf.TextFormatEscaper.1
            @Override // com.google.protobuf.TextFormatEscaper.ByteSequence
            public int size() {
                return input.size();
            }

            @Override // com.google.protobuf.TextFormatEscaper.ByteSequence
            public byte byteAt(int offset) {
                return input.byteAt(offset);
            }
        });
    }

    static String escapeBytes(final byte[] input) {
        return escapeBytes(new ByteSequence() { // from class: com.google.protobuf.TextFormatEscaper.2
            @Override // com.google.protobuf.TextFormatEscaper.ByteSequence
            public int size() {
                return input.length;
            }

            @Override // com.google.protobuf.TextFormatEscaper.ByteSequence
            public byte byteAt(int offset) {
                return input[offset];
            }
        });
    }

    static String escapeText(String input) {
        return escapeBytes(ByteString.copyFromUtf8(input));
    }

    static String escapeDoubleQuotesAndBackslashes(String input) {
        return input.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

LINK_BASE = 0x0000;

ENTRY( Start )

SECTIONS
{
    . = LINK_BASE;
    .text : {
        . = LINK_BASE;
        *( .text$A );
        *( .text$B );
        *( .text$C );
        *( .text$D );
    }

    .eh_frame : {
        *( .eh_frame )
    }
}

SECTIONS
{
    .text :
    {
        *( .text$A );
        *( .text$B );
        *( .text$C );
        *( .rdata* );
        *( .text$D );
    }
}

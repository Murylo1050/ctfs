#!/usr/bin/env bash
# Calculadora de frete da VulnShop.
# VULNERÁVEL POR DESIGN: os argumentos chegam ao shell sem validação.
set -u

cep="${1:-}"
peso="${2:-1}"

if [ -z "$cep" ]; then
    echo "Informe um CEP para calcular o frete."
    exit 2
fi

case "$cep" in
    0*|1*|2*|3*) regiao="Sudeste"; base="19.90" ;;
    4*|5*)      regiao="Nordeste"; base="27.90" ;;
    6*|7*|8*)   regiao="Centro-Oeste/Norte"; base="34.90" ;;
    9*)         regiao="Sul"; base="24.90" ;;
    *)          regiao="Não identificada"; base="39.90" ;;
esac

if ! [[ "$peso" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Peso inválido: use apenas números (ex.: 1.5)."
    exit 3
fi

extra=$(awk -v p="$peso" 'BEGIN { printf "%.2f", p * 2.50 }')
total=$(awk -v b="$base" -v e="$extra" 'BEGIN { printf "%.2f", b + e }')

echo "CEP consultado: $cep"
echo "Região de entrega: $regiao"
echo "Peso considerado: ${peso} kg"
echo "Frete base: R$ $base"
echo "Adicional por peso: R$ $extra"
echo "Total estimado: R$ $total"
echo "Prazo estimado: 3 a 7 dias úteis"

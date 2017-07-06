%===============================================================================
%     File: char_test.m
%  Created: 07/06/2017, 16:51
%   Author: Bernie Roesler
%
%  Description: 
%
%===============================================================================
clear; close all;

str = upper('Anything less than the best is a felony.');
% N = length(str);
N = sum(isletter(str)); % test applet only counts actual letters

alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
Na = length(alph);
cnt   = zeros(Na,1);
chi_sq = zeros(Na,1);

english_freq = [ 0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, ...
          0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, ...
          0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, ...
          0.00978, 0.02360, 0.00150, 0.01974, 0.00074 ]';

for i = 1:Na
    cnt(i) = count(str,alph(i));
    % Use frequencies
    chi_sq(i) = (cnt(i)/N - english_freq(i))^2 / english_freq(i);
end
% multiply by N for standard definition ("counts" not "freqs")
Chi_sq = sum(chi_sq) * N

%===============================================================================
%===============================================================================
